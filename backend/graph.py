import ipaddress
from collections import defaultdict

import networkx as nx

from backend.rules import private


def criticality(ip, config):
    try:
        address = ipaddress.ip_address(ip)
        for entry in config['asset_criticality']:
            if address in ipaddress.ip_network(entry['subnet']): return entry['value']
    except ValueError: pass
    return 1


def path_for(alerts, access, templates):
    graph = nx.MultiDiGraph()
    timeline, sentences, previous = [], [], -1
    for a in sorted(alerts, key=lambda a: (a['ts'], a['file'], a['offset'], a['rule_id'])):
        src = a['src_ip'] or a['user'] or a['host'] or 'unattributed'
        dst = a['dst_ip'] or a['host'] or a['user'] or 'unattributed'
        for entity in (src, dst): graph.add_node(entity, type='asset' if private(entity) else 'entity')
        graph.add_edge(src, dst, technique=a['technique'], ts=a['ts'], alert_id=a['alert_id'])
        if a['user']:
            graph.add_node(a['user'],type='user')
            graph.add_edge(a['user'],dst,technique=a['technique'],ts=a['ts'],alert_id=a['alert_id'],relation='account mentioned in event')
        timeline.append(dict(ts=a['ts'], last_ts=a['last_ts'], rule=a['rule_id'], tech=a['technique'], tname=a['technique_name'],
                             tactic=a['tactic'], stage=a['stage_order'], src=src, dst=dst, sev=a['weight']*10,
                             desc=a['rule_name'], user=a['user'], count=a['count'], file=a['file'], offset=a['offset'],
                             alert_id=a['alert_id'], out_of_order=a['stage_order'] < previous))
        previous = a['stage_order']
        template = templates.get(a['tactic'], templates['default'])
        sentences.append(template.format_map(defaultdict(lambda: 'unknown', {k: v if v != '' else 'unknown' for k,v in a.items()})))
    compromised = {a['src_ip'] for a in alerts if private(a['src_ip'])} | {a['dst_ip'] for a in alerts if private(a['dst_ip'])}
    users = {a['user'] for a in alerts if a['user']}
    observed = {(x['src'],x['dst']) for x in timeline}
    next_hops = []
    for fact in access:
        src, dst = fact['src_ip'], fact['dst_ip']
        if (src in compromised or (fact['user'] and fact['user'] in users)) and private(dst) and (src,dst) not in observed:
            next_hops.append({'from': src or fact['user'], 'to': dst,
                              'why': f"Observed successful access via {fact['rule_id']} at epoch {fact['last_seen']}; historical access is not proof of current permission.",
                              'evidence': fact})
    return dict(nodes=[{'id': n, **attrs} for n,attrs in graph.nodes(data=True)],
                edges=[{'from': s,'to':t,**attrs} for s,t,attrs in graph.edges(data=True)],
                timeline=timeline,next_hops=next_hops,report=' '.join(sentences))
