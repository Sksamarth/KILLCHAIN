"""The seven hackathon metrics, with missing evidence kept separate from failure."""
import math


def scorecard(result, truth, tier_gb=50):
    if type(tier_gb) not in (int, float) or not math.isfinite(tier_gb) or tier_gb <= 0:
        raise ValueError('Chosen tier must be a positive number of decimal GB')
    stats = result.get('stats', {})

    def valid(value, low=0, high=None):
        return (type(value) in (int, float) and math.isfinite(value)
                and value >= low and (high is None or value <= high))

    complete_run = (stats.get('cold_run') is True
                    and stats.get('synthetic_benchmark') is not True
                    and valid(stats.get('bytes')) and stats['bytes'] >= tier_gb * 1e9)
    definitions = [
        ('detection', result.get('detection'), 'fraction', '> 0.70', '> 0.90',
         lambda x: x > .70, lambda x: x > .90, True, 1),
        ('correct_labels', result.get('labels'), 'fraction', '> 0.60', '> 0.85',
         lambda x: x > .60, lambda x: x > .85, True, 1),
        ('attack_path', result.get('attack_paths'), 'fraction', '>= 0.50', '== 1.00',
         lambda x: x >= .50, lambda x: x == 1,
         result.get('exact_membership_checked') is True, 1),
        ('false_alarms', result.get('false_alarms'), 'fraction', '< 0.30', '< 0.10',
         lambda x: x < .30, lambda x: x < .10, True, 1),
        ('processing_time', stats.get('seconds'), 'seconds', '< 10800', '< 3600',
         lambda x: 0 < x < 10800, lambda x: 0 < x < 3600, complete_run, None),
        ('memory', stats.get('cgroup_peak_bytes'), 'bytes', '< 16000000000', '< 8000000000',
         lambda x: 0 < x < 16e9, lambda x: 0 < x < 8e9, complete_run, None),
        ('investigation_speed', result.get('p95_ms'), 'milliseconds', '< 2000', '< 500',
         lambda x: x < 2000, lambda x: x < 500, True, None),
    ]
    metrics = {}
    for name, value, unit, good, great, good_check, great_check, evidence, upper in definitions:
        measured = valid(value, high=upper)
        if name in ('processing_time', 'memory') and measured and value == 0:
            measured = False
        reason = None
        if not measured:
            reason = 'Missing or invalid measurement'
        elif not evidence:
            reason = ('Declare exhaustive planted steps to verify exact path membership'
                      if name == 'attack_path' else
                      'Requires a cold scan of the full chosen tier with measured memory and time')
        metrics[name] = dict(value=value if measured else None, unit=unit,
            good_target=good, great_target=great,
            good=('PASS' if good_check(value) else 'FAIL') if measured and evidence else 'UNVERIFIED',
            great=('PASS' if great_check(value) else 'FAIL') if measured and evidence else 'UNVERIFIED',
            reason=reason)
    blockers = []
    if truth is None:
        blockers.append('Independent planted-attack ground truth is missing')
        for name in ('detection', 'correct_labels', 'attack_path', 'false_alarms'):
            metrics[name].update(good='UNVERIFIED', great='UNVERIFIED', reason=blockers[-1])
    elif truth.get('synthetic') is True:
        blockers.append('Synthetic scenario results cannot certify the real dataset')
    def overall(level):
        statuses = [metric[level] for metric in metrics.values()]
        if 'FAIL' in statuses:
            return 'FAIL'
        return 'UNVERIFIED' if blockers or 'UNVERIFIED' in statuses else 'PASS'
    return dict(chosen_tier_gb=tier_gb, metrics=metrics,
                overall_good=overall('good'), overall_great=overall('great'),
                certification_blockers=blockers,
                supplemental=dict(stage_accuracy=result.get('stages'),
                                  stage_truth_coverage=result.get('stage_coverage')))
