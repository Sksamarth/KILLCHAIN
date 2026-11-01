# Requested detection coverage

The active configuration is `rules/detect.yaml`. `resours/detect.yaml` is the supplied reference and is not loaded by the backend. All eleven requested behaviors have implemented detection paths; this does not establish accuracy on the unlabelled real dataset.

| Behavior | Rules | Trigger |
|---|---|---|
| T1110.001 password guessing | R001, R101 | 20 failures per source IP and user in 300 seconds |
| T1110.003 password spraying | R002, R102 | 10 distinct users per source IP in 300 seconds; R004 separately retains distributed /24 spraying |
| T1078 valid accounts | R010, R110 | Successful authentication from a non-private source address |
| T1021 remote services | R011, R111 | Successful remote authentication from a private source; Windows logon types 3/10 and accepted OpenSSH sessions. R031–R033 are separate network-flow heuristics, not successful-login evidence |
| T1046 service discovery | R020, R120 | 15 distinct destination ports per source/destination pair in 60 seconds |
| T1136.001 local account creation | R130, R131 | Local endpoint account-creation event, Linux useradd message/command, or `net user ... /add` without `/domain` |
| T1548.003 sudo | R140 | Observed sudo command targeting root; excludes listing, validation, and explicit non-root targets |
| T1560 archiving | R150 | tar create, zip create/update, rar a, or 7z/7za a command; extraction/listing is excluded |
| T1041 potential exfiltration | R040, R160 | At least 100,000,000 outbound bytes from a private source to an external destination, with accepted/successful flow status |
| T1071 possible application beacon | R052, R170 | At least 10 distinct event timestamps in a 3,600-second window; intervals 5–600 seconds; population standard deviation / mean interval at most 0.20; transfers 1–4,096 bytes. Endpoint flows require http/https/dns; FortiGate flows use ports 80/443/53 |
| T1070 indicator removal | R180–R183 | Windows 1102, wevtutil/PowerShell log-clear commands (T1070.001), Linux log deletion/vacuum commands (T1070.002), or history clearing (T1070.003) |

Threshold and timing evaluation uses event time over candidates from every file and chunk. Grouping includes destination and protocol for beacon rules, keeping unrelated peers apart. Exact representative offsets and all contributing source locations remain available through the evidence API. Rules for different source families remain distinct detections; thresholds are not merged across FortiGate and endpoint rule IDs.

## Evidence interpretation

Authentication, account creation, archiving and privileged activity also occur legitimately. These detections are investigative signals, not declarations of compromise. Process telemetry establishes that a command was observed; it does not establish successful execution or resulting filesystem changes. Flow volume alone cannot establish that the remote peer is C2 or that transferred bytes contain stolen information. Regular small traffic can be a legitimate heartbeat. Tune thresholds, allowlists and suppression against labelled data from the deployment.

Windows 4672 is detected by R141 as privileged-logon context under T1078, with low weight. It is not Unix sudo and does not independently demonstrate privilege escalation. See [Microsoft's event definition](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672) and [MITRE's sudo technique](https://attack.mitre.org/techniques/T1548/003/).

For event 4720, `TargetDomainName` matching the event computer's short name establishes local scope for R130. A different domain produces T1136.002 (R133); absent scope information produces parent T1136 (R132). The normalized JSON contract may explicitly supply `account_scope` (local/domain/unknown). Linux useradd messages are local-account telemetry.

## Accepted endpoint input

Use one complete event per line in `.jsonl`, `.ndjson`, `.log`, `.txt`, `.syslog` or single-line `.xml`. FortiGate's existing nanosecond key-value format remains supported. The byte offset always points to the original file, not the normalized representation.

Normalized JSONL example:

```json
{"timestamp":"2026-10-23T08:48:26Z","event_type":"process","host":"server1","user":"alice","command":"sudo tar -czf data.tgz /home/alice"}
{"timestamp":"2026-10-23T08:49:26Z","event_type":"login_success","host":"server1","user":"alice","src_ip":"172.16.1.2","dst_ip":"10.1.1.1","remote":true}
{"timestamp":"2026-10-23T08:50:26Z","event_type":"flow","host":"server1","src_ip":"10.1.1.1","dst_ip":"198.51.100.1","dst_port":443,"protocol":"https","bytes":200,"status":"success"}
```

`event_type` accepts login_failure, login_success, account_create, privileged_logon, log_clear, process, sudo_root and flow. Identity fields include host, user, new_user, src_ip and dst_ip. `bytes` means bytes sent, not total bidirectional bytes. `remote:true` is required for a normalized internal remote login. Process commands are tokenized and inspected; no command is executed. Common shell `-c`/`/c`/`-Command` wrappers are supported to a bounded nesting depth; arbitrary scripting languages and encoded commands are not decoded.

The JSON adapter also accepts ECS-style `@timestamp`, `host.name`, `user.name`, `source.ip`, `source.bytes`, `destination.ip`, `destination.port`, `process.command_line`, and `network.protocol`. It accepts Winlogbeat `winlog.event_id`, `winlog.computer_name`, and `winlog.event_data`, including TargetUserName, SubjectUserName, IpAddress, LogonType, CommandLine and TargetDomainName. Supported Windows event IDs are 4624, 4625, 4720, 4672, 4688, 1102 and Sysmon process creation (1) with CommandLine. Native binary `.evtx` and multiline Event Viewer text require export first. Single-line Event XML must contain TimeCreated/SystemTime.

Linux text adapters recognize ISO-prefixed OpenSSH, sudo and useradd messages, for example:

```text
2026-10-23T08:48:26Z server1 sshd[12]: Accepted password for alice from 172.16.1.2 port 50000 ssh2
2026-10-23T08:48:27Z server1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
2026-10-23T08:48:28Z server1 useradd[12]: new user: name=bob, UID=1002, GID=1002
```

Timestamps accept epoch seconds/milliseconds/microseconds/nanoseconds or ISO 8601 with an explicit UTC offset. Yearless syslog and timezone-less dates are rejected rather than assigned an invented time. Malformed/unsupported records and oversized lines remain counted. These schemas have synthetic and integration coverage; no representative Windows/Linux production corpus or independent attack labels were supplied.

## EDR provider reports and generated ECS data

The adapter also accepts `event.kind: alert` records with `event.action` and `threat.technique.id` (a string or array). R200–R204 explicitly map the generator's PowerShell, web beacon, brute-force, registry-persistence and file-encryption report pairs. Action and technique must agree with a configured mapping; arbitrary technique annotations are not automatically promoted into detections. These rows are labelled **Upstream EDR report / provider annotation**. One aggregated provider report remains one matching report, even if a field says it represents many failures. It is not independently reconstructed raw-event evidence.

`process_created`, `network_connection` and ECS event telemetry are accepted without requiring every benign event to match a detection. Missing authentication source addresses or logon types are not invented from endpoint identity. `network.bytes` is not substituted for outbound `source.bytes` because it may be bidirectional. Windows event records continue to use their explicit supported fields.

Scan statistics include `synthetic_lines`, `reported_alert_lines` and `unmapped_report_lines`. The dashboard flags records whose `labels.synthetic` or `labels.simulated_detection` is true and warns about unmapped provider reports. The source byte offset remains the original JSONL location. Simulated labels are not independent ground truth for accuracy measurement.

The legacy preview on port 18766 now forwards API requests to the current Docker app on 8080; the older native API instance is no longer its upstream. Use 8080 for the canonical application. Scan errors now include actionable ValueError/OS error messages instead of hiding every cause behind the same generic failure.

## Operational validation

Parser/rule changes invalidate extraction checkpoints for the next scan; older checkpoint files are retained. Later performance changes completed a resumed real-file Docker run; see PERFORMANCE.md for measured scope. Do not treat a successful small-fixture run as proof of a full-file or 50 GB production pass. See VALIDATION.md for those separate measurements.
