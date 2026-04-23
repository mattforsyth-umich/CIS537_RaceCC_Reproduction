#!/usr/bin/env python3

import os
import sys
import csv
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from collections import defaultdict

# A flow is considered converged if it stays within 20% of fair share
# for at least 5 consecutive samples
TOLERANCE       = 0.2
STABLE_WINDOW   = 5
BOTTLENECK_KBPS = 575

def load_csv(path):
    flows = defaultdict(list)
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows[row['src_ip']].append((
                float(row['elapsed_s']),
                float(row['rate_kbps']),
                float(row['pps'])
            ))
    return flows

def measure_convergence(flows, event_time, active_ips, target_rate):
    # For each flow, parse the samples from the event start and find the first 
    # moment it stays within 20% of the fair share and long enough to count as stable
    per_flow = []

    for ip in active_ips:
        streak       = 0
        converged_at = None

        for t, rate, pps in flows[ip]:
            if t < event_time:
                continue
            if abs(rate - target_rate) / target_rate <= TOLERANCE:
                streak += 1
                if streak >= STABLE_WINDOW and converged_at is None:
                    converged_at = t - event_time
            else:
                streak = 0

        if converged_at is not None:
            per_flow.append(converged_at)
        else:
            return None

    # Use the slowest converged flow as the convergence time
    return max(per_flow) if per_flow else None

def get_convergence_times(flows):
    starts = {ip: samples[0][0] for ip, samples in flows.items()}
    ends   = {ip: samples[-1][0] for ip, samples in flows.items()}
    last_t = max(ends.values())

    events = []

    # Every flow after the first one represents a join event
    for i, (ip, t) in enumerate(sorted(starts.items(), key=lambda x: x[1])):
        if i == 0:
            continue
        events.append((t, 'join', ip, i, i + 1))

    # Flows that stopped before the experiment ended are leave events
    for ip, end_t in sorted(ends.items(), key=lambda x: x[1]):
        if end_t < last_t:
            still_running = sum(1 for e in ends.values() if e > end_t)
            after         = still_running - 1
            if after >= 1:
                events.append((end_t, 'leave', ip, still_running + 1, after))

    events.sort(key=lambda x: x[0])

    results = []
    for event_t, kind, event_ip, n_before, n_after in events:
        fair = BOTTLENECK_KBPS / n_after

        if kind == 'join':
            # Include any flow that had started by the time of this event
            watching = [ip for ip, t in starts.items() if t <= event_t + 1.0]
        else:
            # Only watch flows that were still running after the departure
            watching = [ip for ip in flows if ip != event_ip and ends[ip] > event_t]

        if not watching:
            continue

        conv = measure_convergence(flows, event_t, watching, fair)

        if conv is not None:
            results.append((event_t, n_before, n_after, conv))

    return results

def plot_cdf(all_events, out_path='convergence_cdf.png'):
    if not all_events:
        return

    times  = sorted([e[3] for e in all_events])
    n      = len(times)
    cdf    = [(i + 1) / n for i in range(n)]
    median = times[n // 2]

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.step(times, cdf, where='post', linewidth=2.5,
            color='steelblue', label=f'RaceCC (n={n} events)')
    ax.scatter(times, cdf, color='steelblue', s=40, zorder=5)

    # Median line for all convergence times
    ax.axvline(x=median, color='gray', linestyle='--', linewidth=1, alpha=0.7)
    ax.text(median + 0.2, 0.05, f'median={median:.1f}s', fontsize=9, color='gray')

    ax.set_xlabel('Convergence Time (s)')
    ax.set_ylabel('CDF')
    ax.set_title('ECN — CDF of Convergence Time')
    ax.set_ylim(0, 1.05)
    ax.set_xlim(left=0)
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)

def plot_rates(flows, out_path='rate_fairshare.png'):
    all_times = sorted(set(round(s[0]) for samples in flows.values() for s in samples))
    starts    = {ip: s[0][0] for ip, s in flows.items()}
    ends      = {ip: s[-1][0] for ip, s in flows.items()}
    last_t    = max(ends.values())

    fig, ax = plt.subplots(figsize=(11, 5))
    colors  = plt.rcParams['axes.prop_cycle'].by_key()['color']

    for i, (ip, samples) in enumerate(sorted(flows.items())):
        ax.plot([s[0] for s in samples], [s[1] for s in samples],
                label=ip, linewidth=1.5, color=colors[i % len(colors)])

    # Recompute fair share at each timestep based on how many flows were active
    fair_x, fair_y = [], []
    for t in all_times:
        active = sum(1 for samples in flows.values()
                     if any(abs(s[0] - t) < 1.5 for s in samples))
        if active > 0:
            fair_x.append(t)
            fair_y.append(BOTTLENECK_KBPS / active)
    ax.plot(fair_x, fair_y, 'k--', linewidth=1.5, alpha=0.6, label='Fair share')

    # Mark join and leave events so it's easy to see what triggered each
    # convergence period in the rate trace
    for ip, t in sorted(starts.items(), key=lambda x: x[1])[1:]:
        ax.axvline(x=t, color='gray', linestyle=':', linewidth=1, alpha=0.5)
        ax.text(t + 0.5, ax.get_ylim()[1] * 0.98,
                f'{ip} joins', fontsize=8, color='gray', rotation=90, va='top')

    for ip, end_t in sorted(ends.items(), key=lambda x: x[1]):
        if end_t < last_t:
            ax.axvline(x=end_t, color='red', linestyle=':', linewidth=1, alpha=0.5)
            ax.text(end_t + 0.5, ax.get_ylim()[1] * 0.6,
                    f'{ip} leaves', fontsize=8, color='red', rotation=90, va='top')

    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Rate (Kbps)')
    ax.set_title('ECN — Rate vs Fair Share')
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f'{int(x)}'))
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)

def main():
    paths = sys.argv[1:] if len(sys.argv) > 1 else ['convergence.csv']

    all_events  = []
    first_flows = None

    for path in paths:
        if not os.path.exists(path):
            continue
        flows = load_csv(path)
        if not flows:
            continue
        all_events.extend(get_convergence_times(flows))
        # Keep the first run's flow data for the rate plot
        if first_flows is None:
            first_flows = flows

    if first_flows is None:
        sys.exit(1)

    plot_cdf(all_events)
    plot_rates(first_flows)
    plt.show()

if __name__ == '__main__':
    main()
