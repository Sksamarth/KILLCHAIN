"""Database-wide evidence map, aggregated without loading incident graphs."""
import json

from backend.store import records
from backend.rules import private

ASSET="(e.kind='host' OR (e.kind='ip' AND regexp_matches(e.label,'(?i)^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|169\\.254\\.|fc|fd|fe80:|::1$)')))"


def prepare(db,status='active',stage=None):
    present=db.execute("SELECT count(*) FROM information_schema.tables WHERE table_name IN ('alerts','incident_alerts')").fetchone()[0]
    if present!=2:return False
    where='p.status=?' if status!='all' else 'true'
    args=[status] if status!='all' else []
    if stage is not None:where+=' AND a.stage_order=?';args.append(stage)
    db.execute('''CREATE OR REPLACE TEMP TABLE graph_alerts AS
        SELECT a.*,m.incident_id,p.risk FROM alerts a JOIN incident_alerts m USING(alert_id)
        JOIN incident_paths p ON p.incident_id=m.incident_id WHERE '''+where,args)
    db.execute('''CREATE OR REPLACE TEMP VIEW graph_entities AS
        SELECT DISTINCT a.alert_id,v.id,v.label,v.kind FROM graph_alerts a,
        LATERAL (VALUES ('host:'||a.host,a.host,'host'),('account:'||a.user,a.user,'account'),
            ('ip:'||src_ip,src_ip,'ip'),('ip:'||dst_ip,dst_ip,'ip')) v(id,label,kind) WHERE v.label!='' ''')
    db.execute('''CREATE OR REPLACE TEMP VIEW graph_links AS
        SELECT DISTINCT a.alert_id,v.source,v.target,v.relation FROM graph_alerts a,
        LATERAL (VALUES
          (CASE WHEN src_ip!='' THEN 'ip:'||src_ip END,CASE WHEN host!='' THEN 'host:'||host END,'source'),
          (CASE WHEN host!='' THEN 'host:'||host END,CASE WHEN dst_ip!='' THEN 'ip:'||dst_ip END,'destination'),
          (CASE WHEN a.user!='' THEN 'account:'||a.user END,CASE WHEN host!='' THEN 'host:'||host WHEN dst_ip!='' THEN 'ip:'||dst_ip WHEN src_ip!='' THEN 'ip:'||src_ip END,'account'),
          (CASE WHEN host='' AND src_ip!='' THEN 'ip:'||src_ip END,CASE WHEN host='' AND dst_ip!='' THEN 'ip:'||dst_ip END,'network'))
          v(source,target,relation) WHERE v.source IS NOT NULL AND v.target IS NOT NULL AND v.source!=v.target''')
    return True


def summary(db,status='active',stage=None):
    if not prepare(db,status,stage):return dict(nodes=[],edges=[],totals={},limited=False,remaining_assets=None,confirmed_exploits=None)
    totals=records(db.execute('''SELECT count(*) detections,coalesce(sum(count),0) matching_events,
        count(DISTINCT incident_id) incidents,count(DISTINCT nullif(host,'')) hosts,
        count(DISTINCT nullif("user",'')) accounts,count_if(tactic='Impact') impact_signals,
        count_if(rule_id IN ('R200','R201','R202','R203','R204')) provider_reports,
        min(first_ts) first,max(last_ts) last FROM graph_alerts'''))[0]
    node_count=db.execute('SELECT count(DISTINCT id) FROM graph_entities').fetchone()[0]
    totals['assets']=db.execute('SELECT count(DISTINCT id) FROM graph_entities e WHERE '+ASSET).fetchone()[0]
    edge_count=db.execute('SELECT count(*) FROM (SELECT source,target,relation FROM graph_links GROUP BY ALL)').fetchone()[0]
    nodes=records(db.execute('''SELECT e.id,any_value(e.label) label,any_value(e.kind) kind,
        count(*) detections,sum(a.count) matching_events,count(DISTINCT a.incident_id) incidents,
        max(a.risk) risk,count_if(a.tactic='Impact') impact_signals,min(a.first_ts) first,max(a.last_ts) last
        FROM graph_entities e JOIN graph_alerts a USING(alert_id) GROUP BY e.id
        ORDER BY detections DESC,e.id LIMIT 600'''))
    edges=records(db.execute('''SELECT l.source,l.target,l.relation,count(*) detections,sum(a.count) matching_events,
        count(DISTINCT a.incident_id) incidents,count(DISTINCT nullif(a.host,'')) hosts,
        count_if(a.tactic='Impact') impact_signals,max(a.risk) risk,min(a.first_ts) first,max(a.last_ts) last
        FROM graph_links l JOIN graph_alerts a USING(alert_id) GROUP BY l.source,l.target,l.relation
        ORDER BY detections DESC,l.source,l.target,l.relation LIMIT 1500'''))
    ids={n['id'] for n in nodes};edges=[e for e in edges if e['source'] in ids and e['target'] in ids]
    for node in nodes:
        node['identity_type']=node['kind']
        if node['kind']=='ip' and private(node['label']):node['kind']='host'
    return dict(nodes=nodes,edges=edges,totals=totals,total_nodes=node_count,total_edges=edge_count,
        limited=len(nodes)<node_count or len(edges)<edge_count,remaining_assets=None,confirmed_exploits=None,
        scope='All '+status+' incidents'+(' in the selected stage' if stage is not None else ''),
        interpretation='Detections and provider reports are signals, not confirmed exploitation. Remaining/unaffected assets require a complete inventory and independent adjudication.')


def details(db,node=None,source=None,target=None,relation=None,status='active',stage=None):
    if not prepare(db,status,stage):return dict(techniques=[],incidents=[],evidence=[],metrics={})
    if node:
        condition='alert_id IN (SELECT alert_id FROM graph_entities WHERE id=?)';args=[node]
    else:
        condition='alert_id IN (SELECT alert_id FROM graph_links WHERE source=? AND target=? AND relation=?)';args=[source,target,relation]
    db.execute('CREATE OR REPLACE TEMP TABLE graph_selected AS SELECT * FROM graph_alerts WHERE '+condition,args)
    metrics=records(db.execute('''SELECT count(*) detections,coalesce(sum(count),0) matching_events,
        count(DISTINCT incident_id) incidents,count(DISTINCT nullif(host,'')) hosts,
        count(DISTINCT nullif("user",'')) accounts,count_if(tactic='Impact') impact_signals,
        count_if(rule_id IN ('R200','R201','R202','R203','R204')) provider_reports,
        min(first_ts) first,max(last_ts) last FROM graph_selected'''))[0]
    metrics['assets']=db.execute('SELECT count(DISTINCT e.id) FROM graph_entities e JOIN graph_selected a USING(alert_id) WHERE '+ASSET).fetchone()[0]
    techniques=records(db.execute('''SELECT technique,any_value(technique_name) name,any_value(tactic) tactic,
        count(*) detections,sum(count) matching_events FROM graph_selected GROUP BY technique ORDER BY detections DESC,technique LIMIT 30'''))
    incidents=records(db.execute('''SELECT incident_id id,max(risk) risk,count(*) detections,
        arg_min(rule_name,first_ts) name,min(first_ts) first,max(last_ts) last
        FROM graph_selected GROUP BY incident_id ORDER BY risk DESC,incident_id LIMIT 12'''))
    evidence=records(db.execute('''SELECT alert_id,rule_id,rule_name,technique,host,"user",src_ip,dst_ip,
        first_ts,last_ts,count,bytes,file,"offset" FROM graph_selected ORDER BY first_ts,file,"offset",alert_id LIMIT 8'''))
    return dict(metrics=metrics,techniques=techniques,incidents=incidents,evidence=evidence,
        remaining_assets=None,confirmed_exploits=None,interpretation='Impact signals may be provider annotations. Counts do not confirm exploitation or damage. Remaining/unaffected assets are unknown without inventory and adjudication.')
