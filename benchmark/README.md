# Detector benchmark

Measures how well NeuroLog's detectors work, so changes to them can be compared with numbers instead of judgement calls.

```bash
python -m benchmark.run                          # 5 seeds, printed report (~10 s)
python -m benchmark.run --seeds 10 --json report.json
```

## How it works

[scenarios.py](scenarios.py) generates 40 minutes of logs from three services (`checkout`, `auth-api`, `worker`). Every line comes from a template with known labels: its event type, its failure category, and whether an analyst should care (`incident`). Severity is deliberately not the same as importance. Some warnings are harmless noise, and some real problems are logged at INFO.

| Scenario | What happens | Expected |
|---|---|---|
| `steady_state` | Normal traffic, harmless warnings, one-off harmless events | No spikes |
| `database_outage` | Checkout floods with database timeouts | Spike on `checkout`; top incident is database |
| `auth_attack` | Failed logins with many different user names | Spike on `auth-api`; top incident is auth |
| `novel_failures` | Never-seen failures (segfault, disk quota, TLS expiry) beside harmless one-offs | Outliers flag the failures, not the harmless events |
| `paraphrased_errors` | Known failure types in new wording (`ECONNREFUSED`, `Postgres pool exhausted`, `Too many requests`) | Categories still recognized |

[run.py](run.py) sends each scenario through the same steps as the API. `cluster_messages` sees the newest 100 records, like `/api/run-ml`. `investigate` sees the newest 300, with per-minute counts, like `/api/intelligence`. Results are averaged over several seeds.

## Metrics

| Metric | Meaning |
|---|---|
| `outlier_precision / recall / f1` | DBSCAN outliers vs anomalies. An anomaly is an incident whose template appears at most twice in the newest 100 records. |
| `grouping_ari_*` | Adjusted Rand index between detected groups and true templates. 1.0 means each template is exactly one group. |
| `category_macro_f1`, `category_recall_*` | Keyword category rules vs labeled categories |
| `spike_precision / recall`, `spike_false_alarm_scenarios` | Per-source spike detection across scenarios |
| `risk_roc_auc_alert_level` | Risk score ranking of incidents among warnings, errors and low-severity incidents. `risk_roc_auc_all` also includes routine INFO lines, which makes ranking easy. |
| `risk_precision_at_k` | Share of incidents among the k highest-risk records, where k = min(10, number of incidents) |
| `top_incident_accuracy` | The highest-risk incident matches the scenario's main problem |

## Baseline (5 seeds, when the benchmark was added)

| Metric | Score | What it shows |
|---|---|---|
| Outlier precision | 0.07 | DBSCAN flags almost every rare line, including harmless ones and routine lines with user names or hex IDs |
| Outlier recall | 1.00 | No rare incident is missed |
| Grouping ARI | 0.66 | `normalize_message` only removes numbers and UUIDs, so `user alice` / `user bob` become separate groups. DBSCAN at `eps=0.5` merges nothing beyond that. |
| Category macro F1 | 0.63 | Rate limits (0.0 recall) and heap/OOM wording (0.5) are missed. Numbers like `5021` or `a503f1` match the `502`/`503` rules and mislabel routine lines as upstream. |
| Spike precision / recall | 1.00 / 1.00 | Bursts found with no false alarms |
| Risk AUC (alert level) | 0.98 | Good ranking, but incidents logged at INFO score low |
| Risk precision@k | 0.85 | |
| Top incident accuracy | 1.00 | |

## Changing a detector

1. Run `python -m benchmark.run --json before.json` before the change and `--json after.json` after it.
2. If a score improves, raise its floor in [tests/test_benchmark.py](../tests/test_benchmark.py).
3. When you add a failure mode, add a scenario instead of tuning the detector to the existing ones.

The scenarios are synthetic, so they measure known failure modes, not production accuracy. Labeled real logs (for example, analyst suppressions) are the next step.
