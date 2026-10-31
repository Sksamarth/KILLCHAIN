# Observed log formats

Input: `data/firex-10G.log`, 6,543,120,032 bytes. The filename is not a size measurement.
This inventory examines the first 200,000 lines; it is not a claim that no other formats occur later.
No ground-truth file or earlier tagger.py was found in the supplied locations.

One FortiGate key-value text event per line. Values may be quoted; field order follows the supplied fixture. 
`eventtime` is a 19-digit epoch in nanoseconds; divide by 1,000,000,000 for UTC seconds. 
`date`, `time` and `tz` are retained in source but are not used to parse timestamps. No syslog-year assumption is needed.

Assets are IPs. `devname` identifies a shared firewall, not the attacked host. Users occur primarily in admin events. 
Subnet criticality is configured for 10.10.99.0/24 (management) and 10.10.20.0/24 (DMZ). 
These assignments come from the supplied plan and interfaces observed in the prefix; no authoritative asset inventory was supplied.

The bounded sentbyte reservoir p99.9 is 8,923,113 bytes. This is a prefix estimate, not a full-dataset percentile. The supplied nine-digit exfiltration rule is retained as unverified until ground-truth tuning.

| type/subtype | Lines in prefix |
|---|---:|
| utm/dns | 6,103 |
| traffic/forward | 128,033 |
| event/system | 31,494 |
| utm/webfilter | 9,009 |
| utm/app-ctrl | 6,033 |
| utm/ips | 6,135 |
| event/ha | 1,848 |
| event/sdwan | 1,786 |
| utm/virus | 3,002 |
| event/vpn | 2,923 |
| event/connector | 1,801 |
| event/dhcp | 1,833 |

## utm/dns

```text
date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1501054600" type="utm" subtype="dns" level="information" vd="root" srcip=10.10.40.156 srcport=37918 srcintf="internal4" srcintfrole="lan" dstip=11.113.232.73 dstport=53 dstintf="wan1" dstintfrole="wan" sessionid=235524450 proto=17 action="pass" policyid=20 service="DNS" srccountry="Reserved" dstcountry="Ireland" hostname="nytimes.com"
date=2026-10-23 time=08:48:26 eventtime=1792745306282232000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1501054600" type="utm" subtype="dns" level="information" vd="root" srcip=10.10.20.11 srcport=53067 srcintf="internal2" srcintfrole="dmz" dstip=47.123.169.124 dstport=53 dstintf="wan1" dstintfrole="wan" sessionid=1040491107 proto=17 action="pass" policyid=4 service="DNS" srccountry="Reserved" dstcountry="Singapore" hostname="aljazeera.com"
date=2026-10-23 time=08:48:29 eventtime=1792745309669016000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1501054600" type="utm" subtype="dns" level="information" vd="root" srcip=10.10.50.46 srcport=59471 srcintf="internal5" srcintfrole="lan" dstip=59.172.123.86 dstport=53 dstintf="wan1" dstintfrole="wan" sessionid=3354490096 proto=17 action="pass" policyid=7 service="DNS" srccountry="Reserved" dstcountry="India" hostname="adobe.com"
```

## traffic/forward

```text
date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.40.225 srcport=50951 srcintf="internal4" srcintfrole="lan" dstip=71.38.6.121 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=1309353623 proto=6 action="accept" policyid=4 service="RDP" srccountry="Reserved" dstcountry="Brazil" app="Discord" appcat="Email" apprisk="elevated" duration=274 sentbyte=17865 rcvdbyte=35730 sentpkt=14 rcvdpkt=26
date=2026-10-23 time=08:48:26 eventtime=1792745306705580000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.30.138 srcport=37820 srcintf="internal3" srcintfrole="lan" dstip=147.51.199.61 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=4149697485 proto=6 action="accept" policyid=5 service="HTTPS" srccountry="Reserved" dstcountry="Indonesia" app="SCP" appcat="Collaboration" apprisk="elevated" duration=257 sentbyte=20505 rcvdbyte=82020 sentpkt=16 rcvdpkt=59
date=2026-10-23 time=08:48:26 eventtime=1792745306846696000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=218.214.136.155 srcport=56595 srcintf="wan1" srcintfrole="wan" dstip=10.10.20.180 dstport=443 dstintf="internal2" dstintfrole="dmz" sessionid=310521575 proto=6 action="accept" policyid=2 service="SMB" srccountry="Viet Nam" dstcountry="Reserved" app="HTTPS" appcat="Email" apprisk="medium" duration=261 sentbyte=3895 rcvdbyte=11685 sentpkt=3 rcvdpkt=9
```

## event/system

```text
date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="admin" ui="https(209.50.167.232)" method="https" srcip=209.50.167.232 srcintf="wan1" srcintfrole="wan" dstip=10.10.99.1 dstintf="mgmt" dstintfrole="lan" proto=6 action="login" srccountry="India" dstcountry="Reserved" status="failed" reason="name_invalid" msg="Administrator admin login failed from https(209.50.167.232) because of invalid user name"
date=2026-10-23 time=08:48:27 eventtime=1792745307834508000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="chethan" ui="https(94.154.43.56)" method="https" srcip=94.154.43.56 srcintf="wan1" srcintfrole="wan" dstip=10.10.99.1 dstintf="mgmt" dstintfrole="lan" proto=6 action="login" srccountry="Russian Federation" dstcountry="Reserved" status="failed" reason="name_invalid" msg="Administrator chethan login failed from https(94.154.43.56) because of invalid user name"
date=2026-10-23 time=08:48:28 eventtime=1792745308681204000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="admin" ui="https(104.207.42.233)" method="https" srcip=104.207.42.233 srcintf="wan1" srcintfrole="wan" dstip=10.10.99.1 dstintf="mgmt" dstintfrole="lan" proto=6 action="login" srccountry="Singapore" dstcountry="Reserved" status="failed" reason="name_invalid" msg="Administrator admin login failed from https(104.207.42.233) because of invalid user name"
```

## utm/webfilter

```text
date=2026-10-23 time=08:48:27 eventtime=1792745307128928000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0316013056" type="utm" subtype="webfilter" level="notice" vd="root" srcip=10.10.10.218 srcport=51932 srcintf="internal1" srcintfrole="lan" dstip=106.178.51.139 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=3811264792 proto=6 action="blocked" policyid=10 service="HTTPS" srccountry="Reserved" dstcountry="Germany" hostname="mailchimp.com" url="/" catdesc="Phishing Attempts"
date=2026-10-23 time=08:48:35 eventtime=1792745315878120000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0316013056" type="utm" subtype="webfilter" level="notice" vd="root" srcip=10.10.30.27 srcport=35443 srcintf="internal3" srcintfrole="lan" dstip=151.71.48.55 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=1195131599 proto=6 action="passthrough" policyid=22 service="HTTPS" srccountry="Reserved" dstcountry="Japan" hostname="banamex.com" url="/" catdesc="Spyware"
date=2026-10-23 time=08:48:36 eventtime=1792745316019236000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0316013056" type="utm" subtype="webfilter" level="notice" vd="root" srcip=10.10.99.87 srcport=57104 srcintf="mgmt" srcintfrole="lan" dstip=221.86.121.126 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=2876749108 proto=6 action="passthrough" policyid=24 service="HTTPS" srccountry="Reserved" dstcountry="United States" hostname="superdn.com" url="/" catdesc="Phishing Campaigns"
```

## utm/app-ctrl

```text
date=2026-10-23 time=08:48:29 eventtime=1792745309245668000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1059028704" type="utm" subtype="app-ctrl" level="information" vd="root" srcip=10.10.30.54 srcport=48833 srcintf="internal3" srcintfrole="lan" dstip=11.167.149.240 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=3045747473 proto=6 action="pass" policyid=14 service="HTTPS" srccountry="Reserved" dstcountry="Singapore" app="WinX" appcat="General.Interest" apprisk="low"
date=2026-10-23 time=08:48:40 eventtime=1792745320393832000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1059028704" type="utm" subtype="app-ctrl" level="information" vd="root" srcip=10.10.40.147 srcport=36625 srcintf="internal4" srcintfrole="lan" dstip=15.148.202.231 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=2517273591 proto=6 action="pass" policyid=18 service="HTTPS" srccountry="Reserved" dstcountry="Netherlands" app="WinX" appcat="General.Interest" apprisk="low"
date=2026-10-23 time=08:48:47 eventtime=1792745327026284000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1059028704" type="utm" subtype="app-ctrl" level="information" vd="root" srcip=10.10.99.220 srcport=40721 srcintf="mgmt" srcintfrole="lan" dstip=186.168.237.21 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=3571586372 proto=6 action="pass" policyid=8 service="HTTPS" srccountry="Reserved" dstcountry="Ireland" app="Zendspot" appcat="Storage.Backup" apprisk="high"
```

## utm/ips

```text
date=2026-10-23 time=08:48:32 eventtime=1792745312632452000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10.10.20.38 srcport=40943 srcintf="internal2" srcintfrole="dmz" dstip=2.94.174.249 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=1739006156 proto=6 action="dropped" policyid=7 service="HTTPS" srccountry="Reserved" dstcountry="Indonesia" attack="Apache.security.DDoS-protection" attackid=45716 severity="critical"
date=2026-10-23 time=08:48:40 eventtime=1792745320676064000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10.10.99.152 srcport=55731 srcintf="mgmt" srcintfrole="lan" dstip=96.169.70.73 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=2286013038 proto=6 action="dropped" policyid=21 service="HTTPS" srccountry="Reserved" dstcountry="France" attack="Citrix.ADC.Gateway.Directory.Traversal" attackid=42667 severity="medium"
date=2026-10-23 time=08:48:46 eventtime=1792745326602936000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10.10.10.153 srcport=46381 srcintf="internal1" srcintfrole="lan" dstip=160.77.195.98 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=302555859 proto=6 action="dropped" policyid=22 service="HTTPS" srccountry="Reserved" dstcountry="Ireland" attack="Splunk.security.TSI" attackid=45852 severity="medium"
```

## event/ha

```text
date=2026-10-23 time=08:48:36 eventtime=1792745316160352000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0105048901" type="event" subtype="ha" level="notice" vd="root" logdesc="HA device status" action="N/A" msg="Number of pass member changed."
date=2026-10-23 time=08:48:49 eventtime=1792745329848604000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0105048901" type="event" subtype="ha" level="notice" vd="root" logdesc="HA device status" action="N/A" msg="Number of pass member changed."
date=2026-10-23 time=08:49:12 eventtime=1792745352568280000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0105048901" type="event" subtype="ha" level="notice" vd="root" logdesc="HA device status" action="N/A" msg="Number of pass member changed."
```

## event/sdwan

```text
date=2026-10-23 time=08:48:41 eventtime=1792745321099412000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0113022923" type="event" subtype="sdwan" level="notice" vd="root" logdesc="SD-WAN health-check status" action="N/A" msg="Member status changed. Member in sla."
date=2026-10-23 time=08:48:41 eventtime=1792745321804992000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0113022923" type="event" subtype="sdwan" level="notice" vd="root" logdesc="SD-WAN health-check status" action="N/A" msg="Member status changed. Member out-of-sla."
date=2026-10-23 time=08:49:09 eventtime=1792745349604844000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0113022923" type="event" subtype="sdwan" level="notice" vd="root" logdesc="SD-WAN health-check status" action="N/A" msg="Member status changed. Member in sla."
```

## utm/virus

```text
date=2026-10-23 time=08:48:49 eventtime=1792745329566372000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip=10.10.30.70 srcport=38501 srcintf="internal3" srcintfrole="lan" dstip=173.41.123.248 dstport=80 dstintf="wan1" dstintfrole="wan" sessionid=3392923195 proto=6 action="blocked" policyid=5 service="HTTP" srccountry="Reserved" dstcountry="India" virus="W31/Driverless.TUV!tr" hostname="update-paas-amazon.com" url="/download/setup.exe"
date=2026-10-23 time=08:49:02 eventtime=1792745342125696000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip=10.10.10.120 srcport=59926 srcintf="internal1" srcintfrole="lan" dstip=144.101.231.125 dstport=80 dstintf="wan1" dstintfrole="wan" sessionid=4055690191 proto=6 action="blocked" policyid=13 service="HTTP" srccountry="Reserved" dstcountry="Germany" virus="W29/SpamAssassin.VWX!tr" hostname="office365-dynamicdns.com" url="/download/setup.exe"
date=2026-10-23 time=08:49:02 eventtime=1792745342972392000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip=10.10.10.156 srcport=48249 srcintf="internal1" srcintfrole="lan" dstip=176.235.9.54 dstport=80 dstintf="wan1" dstintfrole="wan" sessionid=2013337560 proto=6 action="blocked" policyid=21 service="HTTP" srccountry="Reserved" dstcountry="Netherlands" virus="W10/hidden!tr" hostname="mail.exective.com" url="/download/setup.exe"
```

## event/vpn

```text
date=2026-10-23 time=08:48:52 eventtime=1792745332106460000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" srcip=190.69.87.98 srcintfrole="lan" dstip=203.0.113.5 dstintfrole="wan" proto=6 action="tunnel-stats" srccountry="Singapore" dstcountry="Reserved" msg="IPsec tunnel statistics"
date=2026-10-23 time=08:48:58 eventtime=1792745338033332000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" srcip=223.98.172.59 srcintfrole="lan" dstip=203.0.113.5 dstintfrole="wan" proto=6 action="negotiate" srccountry="France" dstcountry="Reserved" msg="progress IPsec phase 1"
date=2026-10-23 time=08:49:22 eventtime=1792745362305284000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" user="Tejas.Roy" srcip=97.236.0.46 srcintfrole="lan" dstip=203.0.113.5 dstintfrole="wan" proto=6 action="ssl-login" srccountry="India" dstcountry="Reserved" msg="SSL tunnel statistics"
```

## event/connector

```text
date=2026-10-23 time=08:48:53 eventtime=1792745333940968000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 5.54.46.153"
date=2026-10-23 time=08:48:55 eventtime=1792745335352128000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Failed to connect to FortiGate Cloud 134.85.11.162"
date=2026-10-23 time=08:49:00 eventtime=1792745340150072000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 206.102.44.153"
```

## event/dhcp

```text
date=2026-10-23 time=08:49:00 eventtime=1792745340291188000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0102043008" type="event" subtype="dhcp" level="information" vd="root" logdesc="DHCP Ack log" action="N/A" msg="DHCP server sends a DHCPACK"
date=2026-10-23 time=08:49:20 eventtime=1792745360894124000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0102043008" type="event" subtype="dhcp" level="information" vd="root" logdesc="DHCP Ack log" action="N/A" msg="DHCP server sends a DHCPACK"
date=2026-10-23 time=08:49:38 eventtime=1792745378251392000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0102043008" type="event" subtype="dhcp" level="information" vd="root" logdesc="DHCP Ack log" action="N/A" msg="DHCP server sends a DHCPACK"
```

Only this observed format has a parser. Linux auth/syslog, Windows-style events, web access logs, compressed files and multiline records are not silently claimed as supported.
Rules marked `seen_in_sample: false` remain explicitly unverified. Pattern presence alone does not establish attack-label correctness.
