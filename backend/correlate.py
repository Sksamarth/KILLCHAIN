import hashlib
import json
import heapq
import ipaddress
from collections import Counter, defaultdict
from collections.abc import Mapping
from functools import lru_cache

import yaml
import pyarrow as pa

from backend.graph import criticality, path_for, event_sentence
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
    return ({f'ip:{a[k]}' for k in ('src_ip','dst_ip') if a[k]}
            | {f'{k}:{a[k]}' for k in ('host','user') if a[k]}
            | ({f"user:{a['new_user']}"} if a.get('new_user') else set()))


def components(alerts, config, stream=False):
    # Callers outside the database reader can supply unordered events.
    alerts = sorted(alerts, key=lambda a:(a['first_ts'],a['file'],a['offset'],a['alert_id']))
    degree = Counter(e for a in alerts for e in entities(a))
    stopped = set(config['stoplist'])
    uf, last = UnionFind(len(alerts)), {}
    starts = [a['first_ts'] for a in alerts]
    ends = [a['last_ts'] for a in alerts]
    max_span = config.get('max_incident_span_seconds',4*config['max_gap_seconds'])
    if max_span < config['max_gap_seconds'] or config['max_gap_seconds'] <= 0:
        raise ValueError('Correlation requires a positive gap and incident span >= gap')
    for i,a in enumerate(alerts):
        keys = {(entity,) for entity in entities(a)
                if entity.split(':',1)[1] not in stopped and degree[entity] <= config['entity_degree_cap']}
        # Busy hosts/accounts must not disappear from correlation entirely.
        # Use their joint context, never a common account or shared IP alone.
        host,user,source = a['host'],a['user'],a['src_ip']
        if config.get('compound_entities',True):
            if host and user and host not in stopped and user not in stopped:
                keys.add(('host_user',host,user))
            elif host and source and host not in stopped and source not in stopped:
                keys.add(('host_source',host,source))
            elif user and source and user not in stopped and source not in stopped:
                keys.add(('user_source',user,source))
            if host and a.get('new_user') and host not in stopped and a['new_user'] not in stopped:
                keys.add(('host_user',host,a['new_user']))
        for entity in sorted(keys):
            if entity in last:
                j = last[entity]
                left,right = uf.find(i),uf.find(j)
                start,end = min(starts[left],starts[right]),max(ends[left],ends[right])
                if a['first_ts'] - alerts[j]['last_ts'] <= config['max_gap_seconds'] and end-start <= max_span:
                    uf.union(left,right)
                    root=uf.find(i);starts[root]=start;ends[root]=end
                # Keep the interval that reaches furthest into the future.
                if a['last_ts'] >= alerts[j]['last_ts']: last[entity] = i
            else:
                last[entity] = i
    groups = defaultdict(list)
    for i,a in enumerate(alerts): groups[uf.find(i)].append(a)
    return iter(groups.values()) if stream else list(groups.values())


ROW_FIELDS = ('alert_id','host','user','src_ip','dst_ip','dst_port','new_user','ts','first_ts','last_ts','bytes','count','file','offset')
ROW_INDEX = {key:index for index,key in enumerate(ROW_FIELDS)}
META_FIELDS = ('rule_id','rule_name','technique','technique_name','tactic','kill_chain','stage_order','weight')


class CompactAlert(Mapping):
    """Share rule metadata instead of duplicating wide strings per detection."""
    __slots__ = ('row','metadata')
    def __init__(self,row,metadata): self.row,self.metadata=row,metadata
    def __getitem__(self,key):
        return self.row[ROW_INDEX[key]] if key in ROW_INDEX else self.metadata[key]
    def __iter__(self): return iter((*ROW_FIELDS,*META_FIELDS))
    def __len__(self): return len(ROW_FIELDS)+len(META_FIELDS)


def compact_alerts(db):
    metadata={row[0]:dict(zip(META_FIELDS,row)) for row in db.execute('SELECT DISTINCT '+','.join(META_FIELDS)+' FROM alerts').fetchall()}
    cursor=db.execute('SELECT '+','.join('"'+k+'"' for k in ROW_FIELDS)+',rule_id FROM alerts ORDER BY first_ts,file,"offset",rule_id')
    result=[]
    # fetchall would temporarily retain every wide source tuple as well.
    while batch:=cursor.fetchmany(8192):
        result.extend(CompactAlert(row[:-1],metadata[row[-1]]) for row in batch)
    return result


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
    db.execute('INSERT OR REPLACE INTO cache VALUES (?,?)',['report_templates',json.dumps(templates)])
    count = db.execute('SELECT count(*) FROM alerts').fetchone()[0]
    if count > 1_000_000: raise ValueError('More than 1M reduced alerts: tune aggregation before correlation to retain memory bound')
    alerts = compact_alerts(db)
    networks=[(ipaddress.ip_network(e['subnet']),e['value']) for e in config['asset_criticality']]
    @lru_cache(maxsize=65536)
    def asset_value(value):
        try: address=ipaddress.ip_address(value)
        except ValueError: return 1
        return next((weight for network,weight in networks if address in network),1)
    db.execute('''CREATE OR REPLACE TABLE access_history AS
        SELECT user,src_ip,dst_ip,rule_id,min(ts) first_seen,max(ts) last_seen,count(*) count
        FROM alerts WHERE rule_id IN ('R010','R011','R110','R111')
        GROUP BY user,src_ip,dst_ip,rule_id''')
    access = records(db.execute('SELECT * FROM access_history'))
    db.execute('DELETE FROM incident_paths')
    # Search summaries are rebuilt lazily from the new published generation.
    db.execute('DROP TABLE IF EXISTS incident_search')
    db.execute('CREATE OR REPLACE TABLE incident_alerts (incident_id VARCHAR, alert_id VARCHAR)')
    top={'active':[],'suppressed':[]};paths=[];memberships=[];path_bytes=0
    active_count=critical_count=suppressed_count=0;risky_users=set()
    def flush():
        nonlocal path_bytes
        if paths:
            table=pa.table({name:[row[i] for row in paths] for i,name in enumerate(('incident_id','status','risk','path_json'))})
            db.register('_path_batch',table);db.execute('INSERT INTO incident_paths SELECT * FROM _path_batch');db.unregister('_path_batch');paths.clear();path_bytes=0
        if memberships:
            table=pa.table({'incident_id':[r[0] for r in memberships],'alert_id':[r[1] for r in memberships]})
            db.register('_member_batch',table);db.execute('INSERT INTO incident_alerts SELECT * FROM _member_batch');db.unregister('_member_batch');memberships.clear()
    for group in components(alerts,config,stream=True):
        if len(group) > config['max_component_alerts']: raise ValueError('Incident exceeds configured component limit')
        sequence_ids, bonus = sequences(group,specs)
        stage_counts = [sum(a['stage_order']==n for a in group) for n in range(5)]
        score = min(100, sum(a['weight'] for a in group) * sum(bool(x) for x in stage_counts) * max(asset_value(ip) for a in group for ip in (a['src_ip'],a['dst_ip'])) + bonus)
        reason = ''
        if any(e.split(':',1)[1] in config['allowlists'] for a in group for e in entities(a)): reason='Allowlisted entity'
        elif len(group) < config['min_alerts'] and max(a['weight'] for a in group) < config['min_weight_override']:
            reason='Insufficient independent evidence'
        status = 'suppressed' if reason else 'active'
        iid = str(int(hashlib.sha256('|'.join(sorted(a['alert_id'] for a in group)).encode()).hexdigest()[:12],16))
        # Hundreds of thousands of suppressed singleton signals do not need a
        # NetworkX graph during publication. Their graph is reconstructed on read.
        path = path_for(group,access,templates) if status=='active' else {'lazy_path':True,'report':' '.join(event_sentence(a,templates) for a in sorted(group,key=lambda a:(a['ts'],a['file'],a['offset'],a['rule_id'])))}
        ips = sorted({ip for a in group for ip in (a['src_ip'],a['dst_ip']) if ip})
        name = group[0]['rule_name'] + (f" → {group[-1]['rule_name']}" if len(group)>1 else '')
        item = dict(id=iid,name=name,score=score,risk=score,alert_count=sum(a['count'] for a in group),
                    detection_count=len(group),stage_counts=stage_counts,first=group[0]['first_ts'],last=max(a['last_ts'] for a in group),
                    hosts=len(ips),ips=ips,users=sorted({a['user'] for a in group if a['user']}),summary=path['report'],status=status,
                    suppress_reason=reason,sequence_ids=sequence_ids)
        path.update(item)
        if status=='active':
            active_count+=1;critical_count+=int(score>=75)
            if score>=75:risky_users.update(item['users'])
        else:suppressed_count+=1
        heapq.heappush(top[status],(score,-int(iid),item))
        if len(top[status])>100:heapq.heappop(top[status])
        encoded=json.dumps(path)
        paths.append((iid,status,score,encoded));path_bytes+=len(encoded)
        memberships.extend((iid,a['alert_id']) for a in group)
        if len(paths)>=4096 or path_bytes>=8*1024*1024 or len(memberships)>=8192:flush()
    flush()
    db.execute('CREATE INDEX IF NOT EXISTS membership_incident ON incident_alerts(incident_id)')
    incidents=sorted([t[2] for heap in top.values() for t in heap],key=lambda i:(-i['score'],i['id']))
    stages = [dict(critical=0,total=0) for _ in range(5)]
    tactics = {}
    for a in alerts:
        stage=stages[a['stage_order']]; stage['total']+=1; stage['critical']+=int(a['weight']*10>=75)
        tac=tactics.setdefault(a['tactic'],dict(tactic=a['tactic'],critical=0,non_critical=0))
        tac['critical' if a['weight']*10>=75 else 'non_critical']+=1
    db.execute('''CREATE OR REPLACE TEMP TABLE asset_summary AS
        WITH entities AS (SELECT src_ip ip,technique,rule_name,stage_order,weight FROM alerts WHERE src_ip!=''
            UNION ALL SELECT dst_ip ip,technique,rule_name,stage_order,weight FROM alerts WHERE dst_ip!='' AND dst_ip!=src_ip)
        SELECT ip,max(weight)*10 score,
            list_value(count_if(stage_order=0),count_if(stage_order=1),count_if(stage_order=2),count_if(stage_order=3),count_if(stage_order=4)) stage_counts,
            arg_max(technique,weight) tech,arg_max(rule_name,weight) description FROM entities GROUP BY ip''')
    asset_count,risky_asset_count=db.execute('SELECT count(*),count_if(score>=75) FROM asset_summary').fetchone()
    assets=records(db.execute('SELECT * FROM asset_summary ORDER BY score DESC,ip LIMIT 100'))
    for a in assets:a['top']={'tech':a.pop('tech'),'desc':a.pop('description')}
    overview=dict(totals=dict(incidents=active_count,incidents_critical=critical_count,alerts=len(alerts),
                      alerts_critical=sum(a['weight']*10>=75 for a in alerts),assets=asset_count,assets_risky=risky_asset_count or 0,
                      users=len({a['user'] for a in alerts if a['user']}),users_risky=len(risky_users),suppressed=suppressed_count),
                  stages=stages,tactics=list(tactics.values()),incidents=incidents,assets=assets,scan=stats,
                  limits=dict(incidents_per_status=100,assets=100))
    db.execute('INSERT OR REPLACE INTO cache VALUES (?,?)',['overview',json.dumps(overview)])
