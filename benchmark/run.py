"""Score NeuroLog's detectors on the labeled scenarios.

Run from the repository root:
    python -m benchmark.run                 # 5 seeds, printed report
    python -m benchmark.run --seeds 10 --json benchmark-report.json

Each scenario goes through the same steps as the live API:
1. /api/run-ml clusters the newest 100 records (cluster_messages) and marks outliers.
2. /api/intelligence scores the newest 300 records (investigate), with per-minute
   warning/error counts for spike detection.
The scores are then compared with the labels from benchmark.scenarios.
"""
import argparse
import copy
import json
import statistics
from collections import Counter

from sklearn.metrics import adjusted_rand_score, precision_recall_fscore_support, roc_auc_score

from LogIntel_engine.analysis import normalize_message
from LogIntel_engine.intelligence import category, cluster_messages, investigate, stored_minute_counts
from benchmark.scenarios import build_all

CLUSTER_WINDOW = 100     # /api/run-ml uses recent(owner) with its default limit
ANALYSIS_WINDOW = 300    # /api/intelligence uses recent(owner, 300)
CATEGORIES = ['database', 'memory', 'upstream', 'rate', 'auth']


def _binary(truth, predicted):
    precision, recall, f1, _ = precision_recall_fscore_support(truth, predicted, average='binary', zero_division=0)
    return dict(precision=round(float(precision), 3), recall=round(float(recall), 3), f1=round(float(f1), 3),
                flagged=int(sum(predicted)), positives=int(sum(truth)))


def evaluate_scenario(scenario):
    records, truth = copy.deepcopy(scenario['records']), scenario['truth']

    # 1. Clustering and outliers, exactly as /api/run-ml sees the data.
    window = records[:CLUSTER_WINDOW]
    clusters = cluster_messages(window)
    for record, cluster in zip(window, clusters):
        record['cluster_id'], record['ml_anomaly'] = int(cluster), int(cluster == -1)
    true_templates = [truth[r['_id']]['template'] for r in window]
    counts = Counter(true_templates)
    # An anomaly is a rare event (at most 2 in the window) that an analyst should care about.
    anomaly_truth = [int(truth[r['_id']]['incident'] and counts[t] <= 2) for r, t in zip(window, true_templates)]
    anomaly_pred = [int(c == -1) for c in clusters]
    pattern_keys = [(r['source'], r['severity_label'], normalize_message(r['message'])) for r in window]
    dbscan_groups = [int(c) if c != -1 else -1000 - i for i, c in enumerate(clusters)]  # each outlier is its own group

    # 2. Risk, incidents and spikes, as /api/intelligence computes them.
    analysed = records[:ANALYSIS_WINDOW]
    minute_rows = Counter((r['source'], r['message'].startswith('[GENERATED]'), r['timestamp'][:16])
                          for r in records if r['severity_level'] <= 4)
    result = investigate(analysed, minute_counts=stored_minute_counts((*k, n) for k, n in minute_rows.items()),
                         observed_since=min(r['timestamp'] for r in records))
    scored = result['records']
    incident_truth = [int(truth[r['_id']]['incident']) for r in scored]
    risk = [r['risk_score'] for r in scored]
    # Routine INFO lines make ranking trivially easy, so the alert-level AUC only compares
    # records an analyst might see: warnings and errors, plus incidents at any severity.
    alert_level = [i for i, r in enumerate(scored) if r['severity_level'] <= 4 or incident_truth[i]]
    # k is capped by the number of incidents, so a scenario with 2 incidents can still score 1.0.
    k = min(10, sum(incident_truth))
    top_k = sorted(range(len(scored)), key=lambda i: -risk[i])[:k]
    precision_at_k = sum(incident_truth[i] for i in top_k) / k if k else None
    detected_spikes = {s['source'] for s in result['spikes'] if not s['generated']}
    top_incident = (result['incidents'][0]['category'], result['incidents'][0]['entity']) if result['incidents'] else None

    # 3. Category rules on every analysed record.
    category_truth = [truth[r['_id']]['category'] for r in analysed]
    category_pred = [category(r['message'])[0].replace('routine', 'unclassified') for r in analysed]

    expected = scenario['expected_spikes']
    return dict(
        name=scenario['name'],
        report=dict(
            records=len(records),
            outliers=_binary(anomaly_truth, anomaly_pred),
            template_groups=dict(true=len(counts), normalize_message=len(set(pattern_keys)),
                                 dbscan=len(set(dbscan_groups))),
            spikes=dict(expected=sorted(expected), detected=sorted(detected_spikes)),
            top_incident=dict(expected=scenario['expected_top_incident'], detected=top_incident),
            risk_precision_at_k=None if precision_at_k is None else round(precision_at_k, 3),
        ),
        pooled=dict(anomaly_truth=anomaly_truth, anomaly_pred=anomaly_pred,
                    template_truth=[f"{scenario['name']}|{t}" for t in true_templates],
                    pattern_keys=[f"{scenario['name']}|{k}" for k in pattern_keys],
                    dbscan_groups=[f"{scenario['name']}|{g}" for g in dbscan_groups],
                    incident_truth=incident_truth, risk=risk,
                    alert_truth=[incident_truth[i] for i in alert_level], alert_risk=[risk[i] for i in alert_level],
                    category_truth=category_truth, category_pred=category_pred,
                    spike_tp=len(expected & detected_spikes), spike_fp=len(detected_spikes - expected),
                    spike_fn=len(expected - detected_spikes),
                    false_alarm=int(not expected and bool(detected_spikes)),
                    top_incident_checked=int(scenario['expected_top_incident'] is not None),
                    top_incident_correct=int(scenario['expected_top_incident'] is not None
                                             and tuple(scenario['expected_top_incident']) == top_incident),
                    precision_at_k=precision_at_k or 0, precision_at_k_checked=int(k > 0)))


def summarize(evaluations):
    pool = {key: [] for key in evaluations[0]['pooled'] if isinstance(evaluations[0]['pooled'][key], list)}
    totals = Counter()
    for evaluation in evaluations:
        for key, value in evaluation['pooled'].items():
            if isinstance(value, list):
                pool[key].extend(value)
            else:
                totals[key] += value
    _, category_recall, category_f1, _ = precision_recall_fscore_support(
        pool['category_truth'], pool['category_pred'], labels=CATEGORIES, zero_division=0)
    spike_precision = totals['spike_tp'] / max(totals['spike_tp'] + totals['spike_fp'], 1)
    spike_recall = totals['spike_tp'] / max(totals['spike_tp'] + totals['spike_fn'], 1)
    return {
        'outlier_f1': _binary(pool['anomaly_truth'], pool['anomaly_pred'])['f1'],
        'outlier_precision': _binary(pool['anomaly_truth'], pool['anomaly_pred'])['precision'],
        'outlier_recall': _binary(pool['anomaly_truth'], pool['anomaly_pred'])['recall'],
        'grouping_ari_normalize_message': round(adjusted_rand_score(pool['template_truth'], pool['pattern_keys']), 3),
        'grouping_ari_dbscan': round(adjusted_rand_score(pool['template_truth'], pool['dbscan_groups']), 3),
        'category_macro_f1': round(float(category_f1.mean()), 3),
        **{f'category_recall_{name}': round(float(value), 3) for name, value in zip(CATEGORIES, category_recall)},
        'spike_precision': round(spike_precision, 3),
        'spike_recall': round(spike_recall, 3),
        'spike_false_alarm_scenarios': totals['false_alarm'],
        'risk_roc_auc_all': round(float(roc_auc_score(pool['incident_truth'], pool['risk'])), 3),
        'risk_roc_auc_alert_level': round(float(roc_auc_score(pool['alert_truth'], pool['alert_risk'])), 3),
        'risk_precision_at_k': round(totals['precision_at_k'] / max(totals['precision_at_k_checked'], 1), 3),
        'top_incident_accuracy': round(totals['top_incident_correct'] / max(totals['top_incident_checked'], 1), 3),
    }


def run(seeds=5, first_seed=7):
    runs = []
    for seed in range(first_seed, first_seed + seeds):
        evaluations = [evaluate_scenario(s) for s in build_all(seed * 100)]
        runs.append(dict(seed=seed, summary=summarize(evaluations),
                         scenarios={e['name']: e['report'] for e in evaluations}))
    metrics = runs[0]['summary'].keys()
    aggregate = {m: dict(mean=round(statistics.mean(r['summary'][m] for r in runs), 3),
                         std=round(statistics.pstdev(r['summary'][m] for r in runs), 3)) for m in metrics}
    return dict(seeds=seeds, first_seed=first_seed, metrics=aggregate, runs=runs)


GUIDE = {
    'outlier': 'DBSCAN outliers vs rare incidents (newest 100 records)',
    'grouping': 'Adjusted Rand index of grouping vs true templates (1.0 = perfect)',
    'category': 'Keyword category rules vs labeled category',
    'spike': 'Spike detection per source, across scenarios',
    'risk': 'Risk score ranking of incidents vs non-incidents',
    'top': 'Highest-risk incident matches the scenario\'s main problem',
}


def print_report(report):
    print(f"NeuroLog detector benchmark | {report['seeds']} seeds | {len(report['runs'][0]['scenarios'])} scenarios")
    section = None
    for name, value in report['metrics'].items():
        prefix = name.split('_')[0]
        if prefix != section:
            section = prefix
            print(f"\n{GUIDE.get(prefix, prefix)}")
        print(f"  {name:<34} {value['mean']:>7.3f}  +/- {value['std']:.3f}")
    print('\nFirst seed, per scenario:')
    for name, scenario in report['runs'][0]['scenarios'].items():
        o, g = scenario['outliers'], scenario['template_groups']
        p_at_k = scenario['risk_precision_at_k']
        print(f"  {name:<20} outliers flagged {o['flagged']:>3} (true {o['positives']}, F1 {o['f1']:.2f}) | "
              f"groups true/pattern/dbscan {g['true']}/{g['normalize_message']}/{g['dbscan']} | "
              f"spikes {scenario['spikes']['detected'] or '-'} (expected {scenario['spikes']['expected'] or '-'}) | "
              f"risk P@k {'-' if p_at_k is None else f'{p_at_k:.2f}'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--seeds', type=int, default=5, help='number of random seeds to average over')
    parser.add_argument('--first-seed', type=int, default=7)
    parser.add_argument('--json', help='also write the full report to this file')
    args = parser.parse_args()
    report = run(args.seeds, args.first_seed)
    print_report(report)
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2, default=list)
        print(f'\nFull report written to {args.json}')


if __name__ == '__main__':
    main()
