import hashlib
import json
from collections import Counter, defaultdict

import yaml

from backend.graph import criticality, path_for
from backend.rules import ROOT
from backend.store import records


class UnionFind:
    def __init__(self, size): self.parents = list(range(size)); self.sizes = [1]*size
    def find(self, x):
        while self.parents[x] != x:
            self.parents[x] = self.parents[self.parents[x]]; x = self.parents[x]
        return x
    def union(self, a, b):
        a,b = self.find(a),self.find(b)
        if a == b: return
        if self.sizes[a] < self.sizes[b]: a,b=b,a
        self.parents[b]=a; self.sizes[a]+=self.sizes[b]


def entities(a):
    # src/dst IP share a namespace so lateral movement joins across roles.
    return {f'ip:{a[k]}' for k in ('src_ip','dst_ip') if a[k]} | {f'{k}:{a[k]}' for k in ('host','user') if a[k]}


def components(alerts, config):
    degree = Counter(e for a in alerts for e in entities(a))
    stopped = set(config['stoplist'])
    uf, last = UnionFind(len(alerts)), {}
    for i,a in enumerate(alerts):
        for entity in entities(a):
            if entity.split(':',1)[1] in stopped or degree[entity] > config['entity_degree_cap']: continue
            if entity in last:
                j = last[entity]
                if a['first_ts'] - alerts[j]['last_ts'] <= config['max_gap_seconds']: uf.union(i,j)
            last[entity] = i
    groups = defaultdict(list)
    for i,a in enumerate(alerts): groups[uf.find(i)].append(a)
    return list(groups.values())


def sequences(alerts, specs):
    found, bonus = [], 0
    for spec in specs:
        states = defaultdict(list)
        complete = False
        for a in sorted(alerts, key=lambda a:(a['ts'],a['file'],a['offset'])):
            key = tuple(a.get(k,'') for k in spec['same'])
            if not all(key): continue
            # Advance newest states first; one event cannot satisfy two steps.
            states[key] = [(pos,start) for pos,start in states[key] if a['last_ts']-start <= spec['within']]
            for pos,start in list(states[key]):
                if a['rule_id'] == spec['steps'][pos]:
                    if pos+1 == len(spec['steps']): complete=True
                    else: states[key].append((pos+1,start))
            if a['rule_id'] == spec['steps'][0]: states[key].append((1,a['first_ts']))
            if complete: break
        if complete: found.append(spec['id']); bonus += spec['bonus_score']
    return found,bonus


def build(db, stats):
    config = yaml.safe_load((ROOT/'rules/correlate.yaml').read_text())
    specs = yaml.safe_load((ROOT/'rules/sequence.yaml').read_text())['sequences']
    templates = yaml.safe_load((ROOT/'rules/report.yaml').read_text())['templates']
    count = db.execute('SELECT count(*) FROM alerts').fetchone()[0]
    if count > 1_000_000: raise ValueError('More than 1M reduced alerts: tune aggregation before correlation to retain memory bound')
    alerts = records(db.execute('SELECT * FROM alerts ORDER BY first_ts,file,"offset",rule_id'))
    db.execute('''CREATE OR REPLACE TABLE access_history AS
        SELECT user,src_ip,dst_ip,rule_id,min(ts) first_seen,max(ts) last_seen,count(*) count
        FROM alerts WHERE rule_id IN ('R010','R011','R031','R032','R033')
        GROUP BY user,src_ip,dst_ip,rule_id''')
    access = records(db.execute('SELECT * FROM access_history'))
    db.execute('DELETE FROM incident_paths')
    db.execute('CREATE OR REPLACE TABLE incident_alerts (incident_id VARCHAR, alert_id VARCHAR)')
    incidents, paths = [], []
    for group in components(alerts,config):
        if len(group) > config['max_component_alerts']: raise ValueError('Incident exceeds configured component limit')
        sequence_ids, bonus = sequences(group,specs)
        stage_counts = [sum(a['stage_order']==n for a in group) for n in range(5)]
        score = min(100, sum(a['weight'] for a in group) * sum(bool(x) for x in stage_counts) * max(criticality(ip,config) for a in group for ip in (a['src_ip'],a['dst_ip'])) + bonus)
        reason = ''
        if any(e.split(':',1)[1] in config['allowlists'] for a in group for e in entities(a)): reason='Allowlisted entity'
        elif len(group) < config['min_alerts'] and max(a['weight'] for a in group) < config['min_weight_override']:
            reason='Insufficient independent evidence'
        status = 'suppressed' if reason else 'active'
        iid = str(int(hashlib.sha256('|'.join(sorted(a['alert_id'] for a in group)).encode()).hexdigest()[:12],16))
        path = path_for(group,access,templates)
        ips = sorted({ip for a in group for ip in (a['src_ip'],a['dst_ip']) if ip})
        name = group[0]['rule_name'] + (f" → {group[-1]['rule_name']}" if len(group)>1 else '')
        item = dict(id=iid,name=name,score=score,risk=score,alert_count=sum(a['count'] for a in group),
                    detection_count=len(group),stage_counts=stage_counts,first=group[0]['first_ts'],last=max(a['last_ts'] for a in group),
                    hosts=len(ips),ips=ips,users=sorted({a['user'] for a in group if a['user']}),summary=path['report'],status=status,
                    suppress_reason=reason,sequence_ids=sequence_ids)
        path.update(item)
        incidents.append(item); paths.append((iid,status,score,json.dumps(path)))
        db.executemany('INSERT INTO incident_alerts VALUES (?,?)',[(iid,a['alert_id']) for a in group])
    if paths: db.executemany('INSERT INTO incident_paths VALUES (?,?,?,?)',paths)
    db.execute('CREATE INDEX IF NOT EXISTS membership_incident ON incident_alerts(incident_id)')
    incidents.sort(key=lambda i:(-i['score'],i['id']))
    active = [i for i in incidents if i['status']=='active']
    stages = [dict(critical=0,total=0) for _ in range(5)]
    tactics, assets = {}, {}
    for a in alerts:
        stage=stages[a['stage_order']]; stage['total']+=1; stage['critical']+=int(a['weight']*10>=75)
        tac=tactics.setdefault(a['tactic'],dict(tactic=a['tactic'],critical=0,non_critical=0))
        tac['critical' if a['weight']*10>=75 else 'non_critical']+=1
        for ip in {a['src_ip'],a['dst_ip']} - {''}:
            asset=assets.setdefault(ip,dict(ip=ip,score=0,stage_counts=[0]*5,top={}))
            asset['stage_counts'][a['stage_order']]+=1
            if a['weight']*10>asset['score']: asset.update(score=a['weight']*10,top=dict(tech=a['technique'],desc=a['rule_name']))
    risky_users={u for i in active if i['score']>=75 for u in i['users']}
    overview=dict(totals=dict(incidents=len(active),incidents_critical=sum(i['score']>=75 for i in active),alerts=len(alerts),
                      alerts_critical=sum(a['weight']*10>=75 for a in alerts),assets=len(assets),assets_risky=sum(a['score']>=75 for a in assets.values()),
                      users=len({a['user'] for a in alerts if a['user']}),users_risky=len(risky_users),suppressed=len(incidents)-len(active)),
                  stages=stages,tactics=list(tactics.values()),incidents=active[:100]+[i for i in incidents if i['status']=='suppressed'][:100],assets=sorted(assets.values(),key=lambda a:-a['score'])[:100],scan=stats,
                  limits=dict(incidents_per_status=100,assets=100))
    db.execute('INSERT OR REPLACE INTO cache VALUES (?,?)',['overview',json.dumps(overview)])
