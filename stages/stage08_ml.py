import logging
from tqdm import tqdm
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

ANOMALY_THRESHOLD = 0.7
MAX_EVENTS        = 500_000


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 8: ML-Anomalieerkennung (Isolation Forest)')
    events = ctx.normalized_events

    if len(events) < 10:
        log.info('  Zu wenig Events für ML (<10) — übersprungen')
        ctx.stage_status['stage_08'] = 'ÜBERSPRUNGEN — zu wenig Events'
        return ctx

    if len(events) > MAX_EVENTS:
        log.warning(f'  Sampling: {len(events)} → {MAX_EVENTS} Events')
        import random
        random.seed(42)
        events = random.sample(events, MAX_EVENTS)

    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import LabelEncoder

        le_source = LabelEncoder()
        le_type   = LabelEncoder()
        sources   = le_source.fit_transform([e.source     for e in events])
        types     = le_type.fit_transform([e.event_type for e in events])

        features = []
        for i, e in enumerate(tqdm(events, desc='  Feature-Extraktion', unit='Event', dynamic_ncols=True)):
            features.append([
                e.timestamp.hour,
                e.timestamp.weekday(),
                min(len(e.message), 1000),
                int(sources[i]),
                int(types[i]),
                1 if e.user == 'root' else 0,
                1 if e.ip else 0,
            ])

        X = np.array(features, dtype=float)
        clf = IsolationForest(
            contamination = 0.01,
            random_state  = 42,
            n_estimators  = 100,
        )
        predictions  = clf.fit_predict(X)
        raw_scores   = clf.decision_function(X)

        score_min = raw_scores.min()
        score_max = raw_scores.max()
        score_range = score_max - score_min if score_max != score_min else 1.0
        normalized  = 1.0 - (raw_scores - score_min) / score_range

        anomalies = []
        for i, event in enumerate(events):
            event.anomaly_score = float(normalized[i])
            if predictions[i] == -1:
                anomalies.append(event)

        ctx.anomalies     = anomalies
        ctx.anomaly_scores = [float(s) for s in normalized]
        log.info(f'  {len(anomalies)} Anomalien erkannt von {len(events)} Events')

    except ImportError:
        log.warning('scikit-learn nicht installiert — ML-Stufe übersprungen')
        ctx.stage_status['stage_08'] = 'ÜBERSPRUNGEN — scikit-learn fehlt'

    if ctx.coc:
        ctx.coc.add_entry('stage_08', f'ML: {len(ctx.anomalies)} Anomalien')
    return ctx
