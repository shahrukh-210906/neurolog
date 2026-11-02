"""Labeled, seeded log scenarios for scoring NeuroLog's detectors.

Every record comes from a Template, so its true labels are known:
- template: the event type. Variable fields (IDs, names, durations) don't change it.
- category: the failure category an analyst would assign, using the same keys as
  analysis.RULES, or 'unclassified'.
- incident: whether an analyst should care. Severity alone doesn't decide it: some
  warnings are benign noise, and some real problems are logged at INFO or WARNING.

Timestamps are relative to the `now` passed in, because the detectors compare
against the current time. Each scenario covers 40 complete minutes before `now`.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import random

LABELS = ['EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG']
SOURCES = ('checkout', 'auth-api', 'worker')
MINUTES = 40
NAMES = ['alice', 'bob', 'carol', 'dmitri', 'esther', 'farah', 'gopal', 'hana', 'ivan', 'jun',
         'kofi', 'lena', 'mateo', 'nadia', 'oscar', 'priya', 'quinn', 'rosa', 'sanjay', 'tomas',
         'uma', 'victor', 'wen', 'ximena', 'yusuf', 'zara']
CLIENTS = ['mobile-ios', 'mobile-android', 'web-spa', 'partner-acme', 'partner-globex', 'cli']
JOBS = ['send_email', 'resize_image', 'sync_inventory', 'rebuild_index']
REGIONS = ['eu-west', 'us-east', 'ap-south']


@dataclass(frozen=True)
class Template:
    name: str
    severity: int
    render: object  # callable(rng) -> message text
    category: str = 'unclassified'
    incident: bool = False


def _hex(rng, n=6):
    return ''.join(rng.choice('0123456789abcdef') for _ in range(n))


# Routine traffic. Some fields are high-cardinality text (user names, client names,
# hex request IDs) on purpose, to test whether grouping survives them.
ROUTINE = {
    'checkout': [
        Template('http_ok', 6, lambda r: f'HTTP GET /api/orders/{r.randint(1000, 9999)} status=200 duration_ms={r.randint(4, 180)}'),
        Template('order_created', 6, lambda r: f'Order created order_id={r.randint(10000, 99999)} items={r.randint(1, 6)}'),
        Template('session_started', 6, lambda r: f'Session started for user {r.choice(NAMES)} req={_hex(r)}'),
    ],
    'auth-api': [
        Template('http_ok', 6, lambda r: f'HTTP POST /api/token status=200 duration_ms={r.randint(4, 90)}'),
        Template('token_issued', 6, lambda r: f'Token issued for client {r.choice(CLIENTS)} expires_in=3600'),
        Template('login_ok', 6, lambda r: f'Login succeeded user_id={r.randint(100, 99999)}'),
    ],
    'worker': [
        Template('job_done', 6, lambda r: f'Background job completed job={r.choice(JOBS)} duration_ms={r.randint(20, 4000)}'),
        Template('heartbeat', 6, lambda r: f'Heartbeat ok uptime_s={r.randint(1000, 900000)} queue_depth={r.randint(0, 40)}'),
    ],
}

# Warnings that repeat but don't need attention.
BENIGN_NOISE = {
    'checkout': Template('cache_hit_low', 4, lambda r: f'Cache hit rate low hit_rate=0.{r.randint(40, 69)} region={r.choice(REGIONS)}'),
    'auth-api': Template('slow_request', 4, lambda r: f'Slow request path=/api/userinfo duration_ms={r.randint(1500, 2600)}'),
    'worker': Template('deprecated_setting', 4, lambda r: 'Deprecated setting legacy_mode is enabled'),
}

# One-off events that are unusual but harmless. Flagging these is a false positive.
RARE_BENIGN = [
    ('worker', Template('config_reloaded', 6, lambda r: 'Configuration reloaded from /etc/app/config.yaml')),
    ('worker', Template('report_generated', 6, lambda r: f'Scheduled report generated report=weekly_sales rows={r.randint(500, 5000)}')),
    ('checkout', Template('flag_enabled', 6, lambda r: 'Feature flag new_checkout_flow enabled for 5 percent of traffic')),
    ('auth-api', Template('cache_warmed', 6, lambda r: f'Signing key cache warmed entries={r.randint(10, 90)} elapsed_ms={r.randint(100, 900)}')),
]

# One-off real problems whose wording matches none of the category rules.
NOVEL_INCIDENTS = [
    ('worker', Template('segfault', 2, lambda r: f'Segmentation fault in image resizer worker pid={r.randint(2000, 9000)}', incident=True)),
    ('worker', Template('disk_quota', 3, lambda r: f'Disk quota exceeded on volume data-01 used_gb={r.randint(490, 510)}', incident=True)),
    ('auth-api', Template('tls_expiry', 4, lambda r: 'TLS certificate for api.example.com expires in 2 days', incident=True)),
    ('checkout', Template('null_column', 3, lambda r: f'Unexpected NULL in column orders.customer_id for order {r.randint(10000, 99999)}', incident=True)),
    ('checkout', Template('queue_backlog', 6, lambda r: f'Order queue depth {r.randint(4500, 5200)} exceeds capacity', incident=True)),
]

# Real problems with a known category, worded differently from the rule keywords.
PARAPHRASED = [
    ('checkout', Template('econnrefused_pg', 3, lambda r: 'ECONNREFUSED 10.0.4.12:5432 while acquiring pg connection', 'database', True)),
    ('worker', Template('pg_pool', 3, lambda r: f'Postgres pool exhausted waiting_clients={r.randint(10, 60)}', 'database', True)),
    ('worker', Template('oom_killed', 2, lambda r: f'Out of memory: killed process {r.randint(2000, 9000)} (python)', 'memory', True)),
    ('checkout', Template('heap_high', 4, lambda r: f'Heap usage critical used_pct={r.randint(95, 99)}', 'memory', True)),
    ('checkout', Template('gateway_503', 3, lambda r: f'HTTP 503 from payments-gateway retry={r.randint(1, 3)}', 'upstream', True)),
    ('auth-api', Template('too_many', 4, lambda r: f'Too many requests from client {r.choice(CLIENTS)}', 'rate', True)),
    ('auth-api', Template('jwt_bad_sig', 3, lambda r: f'JWT signature verification failed kid={_hex(r, 8)}', 'auth', True)),
    ('worker', Template('permission_denied', 3, lambda r: 'Permission denied for role analyst on table invoices', 'auth', True)),
]

ISOLATED_UPSTREAM = Template('upstream_reset', 3, lambda r: 'Upstream connection reset by payments-gateway', 'upstream', True)
DB_TIMEOUT = Template('db_timeout', 3, lambda r: f'Database connection timeout duration_ms={r.randint(3000, 9000)}', 'database', True)
DB_RETRY = Template('db_retry', 4, lambda r: f'Retrying database query attempt={r.randint(1, 5)}', 'database', True)
AUTH_FAILED = Template('auth_failed', 3, lambda r: f'Authentication failed invalid token user={r.choice(NAMES)}', 'auth', True)


class _Builder:
    def __init__(self, seed, now):
        self.rng = random.Random(seed)
        self.minute_zero = now.replace(second=0, microsecond=0)
        self.events = []

    def add(self, source, template, minutes_ago):
        """Add one event at a random second within the complete minute `minutes_ago` before now."""
        at = self.minute_zero - timedelta(minutes=minutes_ago) + timedelta(seconds=self.rng.uniform(0, 59.9))
        self.events.append((at, source, template, template.render(self.rng)))

    def baseline(self):
        for minutes_ago in range(MINUTES, 0, -1):
            for source in SOURCES:
                for _ in range(self.rng.randint(2, 4)):
                    self.add(source, self.rng.choice(ROUTINE[source]), minutes_ago)
                if self.rng.random() < 0.25:
                    self.add(source, BENIGN_NOISE[source], minutes_ago)

    def build(self, name, description, expected_spikes=(), expected_top_incident=None):
        self.events.sort(key=lambda e: e[0])
        records, truth = [], {}
        for record_id, (at, source, template, message) in enumerate(self.events, start=1):
            records.append(dict(_id=record_id, uid='benchmark', timestamp=at.isoformat(), source=source,
                                severity_level=template.severity, severity_label=LABELS[template.severity],
                                message=message, ml_anomaly=0, cluster_id=None, entity_id=None, trace_id=None))
            truth[record_id] = dict(template=f'{source}:{template.name}', category=template.category,
                                    incident=template.incident)
        records.reverse()  # newest first, as the API returns them
        return dict(name=name, description=description, records=records, truth=truth,
                    expected_spikes=set(expected_spikes), expected_top_incident=expected_top_incident)


def steady_state(seed, now):
    b = _Builder(seed, now)
    b.baseline()
    for source, template in RARE_BENIGN:
        b.add(source, template, b.rng.randint(1, 5))
    b.add('checkout', ISOLATED_UPSTREAM, 22)
    b.add('checkout', ISOLATED_UPSTREAM, 3)
    return b.build('steady_state', 'Normal traffic with benign warnings and one-off harmless events. Nothing should spike.')


def database_outage(seed, now):
    b = _Builder(seed, now)
    b.baseline()
    for minutes_ago in (3, 2, 1):
        for _ in range(b.rng.randint(14, 18)):
            b.add('checkout', DB_TIMEOUT, minutes_ago)
        for _ in range(3):
            b.add('checkout', DB_RETRY, minutes_ago)
    return b.build('database_outage', 'Checkout floods with database timeouts in the last 3 minutes.',
                   expected_spikes={'checkout'}, expected_top_incident=('database', 'checkout'))


def auth_attack(seed, now):
    b = _Builder(seed, now)
    b.baseline()
    for minutes_ago in (3, 2, 1):
        for _ in range(b.rng.randint(18, 22)):
            b.add('auth-api', AUTH_FAILED, minutes_ago)
    return b.build('auth_attack', 'Auth API sees a burst of failed logins across many user names.',
                   expected_spikes={'auth-api'}, expected_top_incident=('auth', 'auth-api'))


def novel_failures(seed, now):
    b = _Builder(seed, now)
    b.baseline()
    for source, template in NOVEL_INCIDENTS:
        b.add(source, template, b.rng.randint(1, 5))
    for source, template in RARE_BENIGN:
        b.add(source, template, b.rng.randint(1, 5))
    return b.build('novel_failures', 'Never-seen-before failures mixed with harmless one-off events.')


def paraphrased_errors(seed, now):
    b = _Builder(seed, now)
    b.baseline()
    # Three occurrences in three different minutes, so no source reaches spike volume.
    for source, template in PARAPHRASED:
        for minutes_ago in b.rng.sample(range(1, 6), 3):
            b.add(source, template, minutes_ago)
    return b.build('paraphrased_errors', 'Known failure types worded differently from the category keywords.')


SCENARIOS = (steady_state, database_outage, auth_attack, novel_failures, paraphrased_errors)


def build_all(seed=7, now=None):
    now = now or datetime.now(timezone.utc)
    return [scenario(seed + index, now) for index, scenario in enumerate(SCENARIOS)]
