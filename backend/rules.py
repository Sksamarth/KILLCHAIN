import hashlib
import ipaddress
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
STAGES = ['Initial Attempts', 'Persistent Foothold', 'Exploration', 'Propagation', 'Exfiltration & Impact']
NETWORKS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10')]
KV = re.compile(rb'(\w+)=(?:"([^"\r\n]*)"|([^\s]+))')
ALIASES = {'srcip': 'src_ip', 'dstip': 'dst_ip', 'dstport': 'dst_port', 'sentbyte': 'bytes'}


def private(value):
    try:
        ip = ipaddress.ip_address(value)
        return any(ip.version == n.version and ip in n for n in NETWORKS)
    except ValueError:
        return False


def condition(value, expression):
    op = str(expression)
    if op in ('is_private', 'not_private'):
        return private(value) if op == 'is_private' else bool(value) and not private(value)
    if op.startswith(('>', '<')):
        try:
            return float(value) > float(op[1:]) if op[0] == '>' else float(value) < float(op[1:])
        except (ValueError, TypeError):
            return False
    kind, _, arg = op.partition(':')
    if kind == 'eq': return str(value) == arg
    if kind == 'ne': return str(value) != arg
    if kind == 'in': return str(value) in arg.split(',')
    if kind == 'contains': return arg in str(value)
    raise ValueError(f'Unsupported condition: {expression}')


class RuleEngine:
    """Stateless candidate extraction; global SQL windows handle chunk boundaries."""
    def __init__(self, path=ROOT / 'rules/detect.yaml', catalog=ROOT / 'rules/techniques.json'):
        self.path = Path(path)
        self.config = yaml.safe_load(self.path.read_text(encoding='utf-8'))
        known = set(json.loads(Path(catalog).read_text())['techniques'])
        self.rules = self.config['rules']
        self.compiled = []
        ids = set()
        for r in self.rules:
            if r['id'] in ids: raise ValueError('Duplicate rule ID')
            ids.add(r['id'])
            if not re.fullmatch(r'T\d{4}(\.\d{3})?', r['technique']) or r['technique'] not in known:
                raise ValueError(f"Unknown ATT&CK technique: {r['technique']}")
            if r['tactic'] not in self.config['tactics']: raise ValueError('Unknown tactic')
            if r['type'] not in ('match', 'threshold', 'distinct_threshold'): raise ValueError('Unknown rule type')
            pattern = re.compile(r['match'].encode())
            fields = set(pattern.groupindex) | {'src_net24'}
            if not set(r.get('where', {})) <= fields: raise ValueError('Condition references uncaptured field')
            for v in r.get('where', {}).values(): condition('', v)
            if r['type'] != 'match':
                if r.get('window', 0) <= 0 or r.get('count', 0) < 2: raise ValueError('Invalid threshold')
                if not set(r.get('group_by', [])) <= fields: raise ValueError('Invalid grouping field')
                if r['type'] == 'distinct_threshold' and r.get('distinct') not in fields: raise ValueError('Invalid distinct field')
            self.compiled.append((r, r.get('prefilter', '').encode(), pattern))
        seq = yaml.safe_load((self.path.parent / 'sequence.yaml').read_text())
        for s in seq['sequences']:
            if not set(s['steps']) <= ids: raise ValueError('Sequence references unknown rule')
        self.fingerprint = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def candidates(self, line, file, offset):
        matches = [(r, p.search(line)) for r, literal, p in self.compiled if literal in line]
        matches = [(r, m) for r, m in matches if m]
        if not matches: return
        values = {k.decode(): (a or b).decode('utf-8', 'replace') for k, a, b in KV.findall(line)}
        try: ts = int(values['eventtime']) // 1_000_000_000
        except (KeyError, ValueError): return
        base = {ALIASES.get(k, k): v for k, v in values.items()}
        for r, m in matches:
            fields = dict(base)
            fields.update({k: v.decode('utf-8', 'replace') for k, v in m.groupdict().items() if v is not None})
            src = fields.get('src_ip', '')
            try: fields['src_net24'] = str(ipaddress.ip_network(src + '/24', strict=False))
            except ValueError: fields['src_net24'] = ''
            if not all(condition(fields.get(k, ''), v) for k, v in r.get('where', {}).items()): continue
            stage = self.config['tactics'][r['tactic']]['kill_chain']
            if r['tactic'] == 'Credential Access' and private(src): stage = 'Propagation'
            alert = {k: fields.get(k, '') for k in ('host', 'user', 'src_ip', 'dst_ip', 'dst_port', 'new_user')}
            alert.update(ts=ts, first_ts=ts, last_ts=ts, bytes=int(fields.get('bytes', 0)), count=1,
                         rule_id=r['id'], rule_name=r['name'], technique=r['technique'], technique_name=r['technique_name'],
                         tactic=r['tactic'], kill_chain=stage, stage_order=STAGES.index(stage), weight=r['weight'],
                         file=file, offset=offset, group_key=json.dumps([fields.get(k, '') for k in r.get('group_by', [])]),
                         distinct_value=fields.get(r.get('distinct', ''), ''), kind=r['type'],
                         window=r.get('window', 0), threshold=r.get('count', 0))
            alert['alert_id'] = hashlib.sha256(f'{file}:{offset}:{r["id"]}'.encode()).hexdigest()[:24]
            yield alert
