from datetime import datetime, timezone

from benchmark.run import run
from benchmark.scenarios import build_all
from LogIntel_engine.intelligence import cluster_messages

# Floors sit just below the scores measured when the benchmark was added.
# When a detector improves, raise its floor so the gain can't be lost silently.
FLOORS = {
    'outlier_recall': 0.95,
    'grouping_ari_normalize_message': 0.6,
    'category_macro_f1': 0.6,
    'spike_precision': 1.0,
    'spike_recall': 1.0,
    'risk_roc_auc_alert_level': 0.95,
    'risk_precision_at_k': 0.8,
    'top_incident_accuracy': 1.0,
}


def test_detectors_meet_benchmark_floors():
    metrics = run(seeds=1)['metrics']
    below = {name: metrics[name]['mean'] for name, floor in FLOORS.items() if metrics[name]['mean'] < floor}
    assert not below, f'Detector scores fell below their floors: {below}'
    assert metrics['spike_false_alarm_scenarios']['mean'] == 0


def test_scenarios_are_reproducible_and_fully_labeled():
    now = datetime(2026, 11, 2, 12, 0, 30, tzinfo=timezone.utc)
    first, second = build_all(3, now), build_all(3, now)
    assert [s['records'] for s in first] == [s['records'] for s in second]
    for scenario in first:
        ids = [r['_id'] for r in scenario['records']]
        assert ids == sorted(ids, reverse=True)
        assert set(ids) == set(scenario['truth'])
        assert all(r['timestamp'] < now.isoformat() for r in scenario['records'])


def test_cluster_messages_marks_outliers_and_handles_empty_vocabulary():
    records = [dict(message=f'Database connection timeout duration_ms={n}') for n in range(4)]
    records.append(dict(message='Segmentation fault in image resizer'))
    clusters = cluster_messages(records)
    assert list(clusters[:4]) == [clusters[0]] * 4 and clusters[0] != -1
    assert clusters[4] == -1
    assert cluster_messages([dict(message='the and of'), dict(message='a an')]) is None
