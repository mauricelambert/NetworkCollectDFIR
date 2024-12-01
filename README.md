![NetworkCollectDFIR Logo](https://mauricelambert.github.io/info/python/security/NetworkCollectDFIR_small.png "NetworkCollectDFIR logo")

# NetworkCollectDFIR

## Description

This script collects data for incident response and forensic (useful for CTF and DFIR challenges !).

> This script has been written in forensic lessons and challenges for certification. It's a little script to reduce time for analysis and basic detection. Output are: the JSON report and extracted files.
>> Detections for suspicious activity will added in the future (check the *to do* list)

## Requirements

This package require:
 - python3
 - python3 Standard Library
 - Scapy

## Installation

### Git

```bash
python3 -m pip install scapy
git clone "https://github.com/mauricelambert/NetworkCollectDFIR.git"
cd "NetworkCollectDFIR"
```

### Wget

```bash
wget https://github.com/mauricelambert/QueryApacheAccessLog/archive/refs/heads/main.zip
unzip main.zip
cd QueryApacheAccessLog-main
```

## Usages

### Command line

```bash
python3 network_ir_collect.py <file.pcap>
```

## To Do

 - [X] Extract SMB files and generates hashes (MD5, SHA1, SHA256)
 - [X] Extract HTTP files and generates hashes (MD5, SHA1, SHA256)
 - [ ] Extract FTP files
 - [ ] Port scan (lot of TCP connection without `ACK`, statistcs are generated and reported)
 - [ ] HTTP bruteforce path (hacktools like `dirb`, `dirbuster`, `ffuf`, `gobuster`, bruteforce HTTP path to discover hidden or misconfigured files) (lot of 404 error pages and lot of path, statistcs are generated and reported)
 - [ ] Hostname spoofing (spoof local hostname to perform MITM attack, multiples local name for an IP address, data are parsed, there is no statistics)
 - [ ] ARP spoofing (multiples IP addresses for one MAC address (false positive with router), statistcs are generated and reported)
 - [ ] ARP scan (lot of requests for differents IP address wihtout responses)
 - [ ] Ping scan (lot of requests for differents IP address wihtout responses)
 - [ ] RPC SID bruteforce
 - [ ] LDAP enumeration
 - [ ] SMB enumeration
 - [ ] HTTP authentication bruteforce (lot of Authorization header value)
 - [ ] FTP authentication bruteforce (lot of user/password value)
 - [ ] Kerberos authentication bruteforce (lot of requests in short time)
 - [ ] NTLM authentication bruteforce
 - [ ] AS-REP roasting
 - [ ] Kerberoasting
 - [X] List TCP sessions (IP addresses, ports, data size, start, end, files, ...)
 - [X] Roles detections (DNS server, LDAP server, Kerberos server, NTP server)
 - [X] Statistics by IP (how many IP contected, how many ports contacted)
 - [X] IP statistics (how many packets with IP address (as source or destination))
 - [X] TCP statistics (SYN, ACK, CLOSE, RESET)
 - [X] UDP statistics
 - [X] HTTP statistics
 - [ ] RPC statistics
 - [ ] WinRM statistics
 - [X] List all flux between two IP addresses
 - [X] List all TCP flux
 - [X] List all UDP flux
 - [X] List all name resolution (DNS, mDNS, LLMNR, NetBios)
 - [X] Datetime of the first packet (IP, flux between two IP addresses, TCP by destination port and IP, UDP by destination port and IP, by protocol and IP, name resolution)
 - [X] SMB informations (IP, hostname, file path, share) with datetime for the first session
 - [X] HTTP informations (host, user-agent, path (by method), status code, server, content type) with datetime for the first session
 - [X] NTP with packet datetime (to identify problems with datetime, some hacktools can generate invalid kerberos tickets by datetime mistake)
 - [X] LDAP filters (hostname, domain, Domain GUID/SID, user) with datetime for the first session
 - [X] RPC informations (machine name) with datetime for the first session
 - [X] Kerberos informations (cname, sname, address/hostname) with datetime for the first session

## Links

 - [Github](https://github.com/mauricelambert/NetworkCollectDFIR)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
