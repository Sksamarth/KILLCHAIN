import json

from backend.validation import generate,validate


def test_truth_is_deterministic_and_points_to_original_lines(tmp_path):
    first,truth=generate(tmp_path/'a',seed=701,background=20)
    second,other=generate(tmp_path/'b',seed=701,background=20)
    assert first.read_bytes()==second.read_bytes() and truth==other
    assert len(truth['attacks'])==2 and truth['benign']
    data=first.read_bytes()
    for attack in truth['attacks']:
        assert [s['offset'] for s in attack['steps']]==sorted(s['offset'] for s in attack['steps'])
        for step in attack['steps']:
            record=json.loads(data[step['offset']:].split(b'\n',1)[0])
            assert record['timestamp']>0 and 'technique' not in record and 'threat' not in record


def test_validation_exposes_contextual_false_positive_without_faking_pass(tmp_path):
    result=validate(tmp_path/'validation',seed=809,background=80)
    assert result['detection']==result['labels']==result['attack_paths']==1
    assert result['false_alarms']==1/3 and result['accuracy_gate']=='FAIL'
    assert result['benign_records_in_active_incidents']==2
    assert {row['case'] for row in result['benign_failures']}=={'authorized_backup'}
