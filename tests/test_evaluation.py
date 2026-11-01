import sys

import pytest

from backend.evaluate import main, score


def test_independent_attacks_merged_into_one_incident_fail_paths():
    steps = [dict(file='a.log', offset=i, technique='T1078') for i in (1, 2)]
    truth = {'attacks': [dict(id=str(i), steps=[step]) for i, step in enumerate(steps)]}
    timeline = [dict(file=s['file'], offset=s['offset'], tech=s['technique']) for s in steps]
    result = score([dict(id='merged', timeline=timeline)], truth)
    assert result['detection'] == result['labels'] == 1
    assert result['attack_paths'] == 0
    assert result['merged_incidents'] == 1
    separate = [dict(id=str(i), timeline=[event]) for i, event in enumerate(timeline)]
    assert score(separate, truth)['attack_paths'] == 1


def test_missing_truth_does_not_contact_api(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['evaluate', '--truth', str(tmp_path / 'missing.json')])
    def unexpected_session():
        pytest.fail('Missing truth must be handled before opening an API session')
    monkeypatch.setattr('backend.evaluate.requests.Session', unexpected_session)
    assert main() == 2
    assert 'UNVERIFIED' in capsys.readouterr().out
