"""Line-oriented endpoint adapters. Never guess a year or a timezone."""
import datetime as dt
import ipaddress
import json
import re
import shlex
import xml.etree.ElementTree as ET

ISO_PREFIX = re.compile(r'^(?:<\d+>(?:1 )?)?(?P<stamp>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))\s+(?P<host>\S+)\s+(?P<message>.*)$')


def command_behavior(command, depth=0):
    """Inspect the executable and arguments, never execute supplied commands."""
    if depth > 3: return '', False
    try:
        # Windows paths must retain backslashes; Unix quoting uses POSIX rules.
        lexer = shlex.shlex(command, posix=not bool(re.search(r'[A-Za-z]:\\',command)), punctuation_chars=';&|')
        lexer.whitespace_split=True;lexer.commenters=''
        tokens=[t.strip('"\'') for t in lexer]
    except ValueError: return '', False
    if not tokens: return '', False
    # Inspect shell command segments individually; quoted text stays one token.
    for index, token in enumerate(tokens):
        if token in (';','&&','||','|'):
            left=command_behavior(shlex.join(tokens[:index]),depth+1)
            right=command_behavior(shlex.join(tokens[index+1:]),depth+1)
            return left[0] or right[0],left[1] or right[1]
    executable=tokens[0].replace('\\','/').rsplit('/',1)[-1].lower().removesuffix('.exe')
    args=tokens[1:];low=[a.lower() for a in args]
    if executable in ('sh','bash','dash','zsh','cmd','powershell','pwsh'):
        for flag in ('-c','/c','-command'):
            if flag in low:
                return command_behavior(' '.join(args[low.index(flag)+1:]),depth+1)
    if executable=='sudo':
        root=True;index=0
        while index<len(args) and args[index].startswith('-'):
            option=args[index]
            if option in ('-l','--list','-v','--validate','-k','-K','--help','--version'): return '',False
            if option in ('-u','--user'):
                index+=1
                if index>=len(args): return '',False
                root=args[index] in ('root','#0','0')
            elif option.startswith('--user='): root=option.split('=',1)[1] in ('root','#0','0')
            elif option.startswith('-u') and len(option)>2: root=option[2:] in ('root','#0','0')
            elif option in ('-g','--group','-h','--host','-p','--prompt','-C','-T'): index+=1
            index+=1
        nested=command_behavior(shlex.join(args[index:]),depth+1) if index<len(args) else ('',False)
        return nested[0],root and (index<len(args) or '-i' in args or '-s' in args)
    if executable=='useradd' and args and not {'--help','--version','-h'}.intersection(low): return 'account_create',False
    if executable=='net' and low[:1]==['user'] and '/add' in low and '/domain' not in low: return 'account_create',False
    if executable=='tar' and args and ('--create' in args or any(a.startswith('-') and not a.startswith('--') and 'c' in a[1:] for a in args) or ('c' in args[0] and not args[0].startswith('-') and args[0].isalpha())): return 'archive',False
    if executable=='zip' and args and not any(a in ('--help','--version') or (a.startswith('-') and any(c in a[1:] for c in 'dhvT')) for a in args): return 'archive',False
    if executable in ('rar','7z','7za') and low[:1]==['a']: return 'archive',False
    if executable=='history' and '-c' in args or executable=='clear-history': return 'history_clear',False
    if executable=='wevtutil' and low[:1] in (['cl'],['clear-log']) and len(args)>1 or executable=='clear-eventlog' and args: return 'windows_log_clear',False
    if executable=='journalctl' and any(a.startswith('--vacuum-') for a in low): return 'linux_log_clear',False
    if executable in ('rm','truncate') and any(a.startswith('/var/log/') for a in args): return 'linux_log_clear',False
    return '',False


def timestamp(value):
    if value is None or isinstance(value, bool): return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r'\d+(?:\.\d+)?', str(value)):
            number = float(value)
            if number >= 1e17: number /= 1e9
            elif number >= 1e14: number /= 1e6
            elif number >= 1e11: number /= 1e3
            return int(number) if 0 <= number <= 32503680000 else None
        parsed = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return int(parsed.timestamp()) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError, OSError): return None


def flatten(value, prefix='', result=None):
    result = {} if result is None else result
    if isinstance(value, dict):
        for key, item in value.items(): flatten(item, prefix+'.'+key if prefix else key, result)
    else: result[prefix.lower()] = value
    return result


def ip(value):
    try:
        address = ipaddress.ip_address(str(value))
        return str(address.ipv4_mapped or address) if address.version == 6 else str(address)
    except ValueError: return ''


def endpoint(line):
    """Return (canonical bytes, epoch seconds) or None for unsupported records.

    Supports JSONL (normalized/ECS/Winlogbeat), single-line Windows Event XML,
    and timezone-qualified ISO syslog containing OpenSSH/sudo/useradd messages.
    """
    text = line.decode('utf-8', 'replace').strip()
    try:
        if text.startswith('{'):
            obj = json.loads(text)
            if not isinstance(obj, dict): return None
            fields = flatten(obj)
        elif text.startswith('<') and '<Event' in text[:150]:
            if '<!DOCTYPE' in text or '<!ENTITY' in text: return None
            root = ET.fromstring(text)
            fields = {}
            for node in root.iter():
                tag = node.tag.rsplit('}', 1)[-1]
                if tag == 'Data' and node.get('Name'): fields[node.get('Name').lower()] = node.text or ''
                elif tag == 'TimeCreated': fields['timestamp'] = node.get('SystemTime')
                elif tag in ('EventID','Computer'): fields[tag.lower()] = node.text or ''
        else:
            match = ISO_PREFIX.match(text)
            if not match: return None
            fields = {'timestamp':match['stamp'], 'host':match['host'], 'message':match['message']}
    except (ValueError, ET.ParseError, RecursionError): return None

    def pick(*names, default=''):
        for name in names:
            for key in (name, 'winlog.event_data.'+name, 'event.eventdata.'+name):
                value = fields.get(key.lower())
                if value is not None and value != '': return str(value)
        return default

    ts = timestamp(pick('@timestamp','timestamp','ts','eventtime','system.timecreated.systemtime','event.system.timecreated.systemtime'))
    if ts is None: return None
    event = pick('event_type','event.action','event').lower()
    code = pick('event_id','eventid','event.code','winlog.event_id','event.system.eventid')
    host = pick('host.name','host','computer','winlog.computer_name','event.system.computer')
    user = pick('user.name','user','targetusername','subjectusername')
    new_user = pick('new_user')
    account_scope = pick('account_scope',default='local').lower()
    src = ip(pick('source.ip','src_ip','srcip','ipaddress'))
    dst = ip(pick('destination.ip','dst_ip','dstip'))
    command = pick('process.command_line','command_line','command','commandline')
    message = pick('message')
    logon_type = pick('logontype','logon_type')
    remote = pick('remote',default='false').lower() == 'true'
    status = pick('status','event.outcome',default='success').lower()
    source_action=event
    technique_values=fields.get('threat.technique.id',[])
    if isinstance(technique_values,str): technique_values=[technique_values]
    if not isinstance(technique_values,list): technique_values=[]
    reported_techniques=','.join(t for t in technique_values[:32] if isinstance(t,str) and re.fullmatch(r'T\d{4}(?:\.\d{3})?',t))
    synthetic=pick('labels.synthetic').lower()=='true' or pick('labels.simulated_detection').lower()=='true'
    if code in ('4624','4625'):
        event = 'login_success' if code == '4624' else 'login_failure'
        remote = logon_type in ('3','10')
        status = 'success' if code == '4624' else 'failure'
    elif code == '4720':
        event = 'account_create';new_user = pick('targetusername');user = pick('subjectusername')
        domain = pick('targetdomainname')
        account_scope = ('local' if domain.casefold()==host.split('.')[0].casefold() else 'domain') if domain and host else 'unknown'
    elif code == '4672': event = 'privileged_logon';user = pick('subjectusername','user.name','user')
    elif code == '1102': event = 'log_clear';user = pick('subjectusername','user.name','user')
    elif code in ('4688','1') and command: event = 'process'
    # Only service-tagged OpenSSH messages count as authentication evidence.
    if re.search(r'\bsshd(?:\[\d+\])?:', message):
        auth = re.search(r'\b(Failed|Accepted) (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(\S+) from (\S+)', message)
        if auth:
            event = 'login_success' if auth[1] == 'Accepted' else 'login_failure'
            user, src, remote = auth[2], ip(auth[3]), True
            status = 'success' if auth[1] == 'Accepted' else 'failure'
    if re.search(r'\bsudo(?:\[\d+\])?:', message):
        sudo = re.search(r':\s*(\S+)\s*:.*?\bUSER=root\s*;\s*COMMAND=(.+)', message)
        if sudo and not re.search(r'authentication failure|NOT in sudoers|command not allowed', message, re.I):
            user, command, event = sudo[1], 'sudo -u root '+sudo[2], 'sudo_root'
    if re.search(r'\buseradd(?:\[\d+\])?:', message):
        created = re.search(r'new user:\s*name=([^,\s]+)', message)
        if created: event, new_user = 'account_create', created[1]
    # Normalized explicit events are a documented interchange contract.
    aliases = {'authentication_failure':'login_failure','authentication_success':'login_success','network_flow':'flow','network_connection':'flow','process_start':'process','process_created':'process'}
    event = aliases.get(event,event)
    if pick('event.kind')=='alert':
        # Preserve provider annotations as reports, not independently observed
        # raw authentication failures or beacon intervals.
        event='reported_alert'
    elif event not in {'login_success','login_failure','account_create','privileged_logon','log_clear','process','sudo_root','flow'} and pick('event.kind')=='event':
        event='telemetry'
    if event not in {'login_success','login_failure','account_create','privileged_logon','log_clear','process','sudo_root','flow','reported_alert','telemetry'}:
        return None
    if event == 'login_failure': status = 'failure'
    try:
        size = max(0,int(pick('source.bytes','bytes_sent','sentbyte','bytes',default='0')))
        port = int(pick('destination.port','dst_port','dstport',default='0'))
        if size > 9223372036854775807 or not 0 <= port <= 65535: return None
    except ValueError: return None
    behavior, sudo = command_behavior(command) if command else ('',False)
    if event == 'sudo_root': sudo=True
    values = dict(event=event,host=host,user=user,new_user=new_user,src_ip=src,dst_ip=dst,
                  dst_port=port,bytes=size,remote=str(remote).lower(),status=status,
                  protocol=pick('network.protocol','protocol').lower(),command_kind=behavior,sudo_root=str(sudo).lower(),account_scope=account_scope,
                  reported_action=source_action,reported_techniques=reported_techniques,source_synthetic=str(synthetic).lower())
    def quote(value): return json.dumps(str(value), ensure_ascii=True)
    canonical = ' '.join(k+'='+quote(v) for k,v in values.items())
    # Command is last, so shell quotes cannot inject canonical identity fields.
    canonical += ' command='+command.replace('\r',' ').replace('\n',' ')
    return canonical.encode(), ts
