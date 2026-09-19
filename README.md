# Open-Source SOC Automation Framework for IOC-driven Incident Response

A fully open-source Security Operations Centre that automates the indicator-of-compromise
lifecycle — from endpoint detection through threat-intelligence enrichment to case creation —
with no analyst in the loop.

Built and evaluated as a B.Sc. graduation project, Faculty of Information Technology,
Sabha University (2025–2026).

**Measured in an isolated lab: MTTD 3.28–6.26 s · MTTR 10.79–19.04 s · 100% completion across 40 runs.**

---

## What it does

A Wazuh alert fires on an endpoint. Within seconds, without anyone touching a keyboard:

1. The alert is pushed to n8n by webhook.
2. IOCs (IP, domain, URL, file hash) are extracted from free-text command lines and log fields.
3. Private and loopback addresses are filtered out; a primary indicator is ranked.
4. MISP is queried for a known-indicator match.
5. On a match — or on a Wazuh rule level ≥ 12 with no indicator at all — a TheHive alert is created.
6. Every observable is routed to the right Cortex analyser: VirusTotal for hashes, AbuseIPDB for
   IPs, AlienVault OTX for domains and URLs.

The analyst opens TheHive to a case that is already enriched.

## Architecture

Four layers, integrated over REST APIs and webhooks:

| Layer | Component | Role |
|---|---|---|
| Detection | Wazuh 4.7 + Sysmon 15 | Endpoint telemetry, rule matching, alerting |
| Orchestration | n8n 1.0 | Webhook intake, IOC extraction, conditional triage |
| Enrichment | MISP 2.4, Cortex 3.1 | Local intel matching, external analyser execution |
| Case management | TheHive 5.1 | Alerts, observables, tasks, investigation record |

Deployed as ~12 Docker containers on Ubuntu Server 22.04, with Windows 11 endpoints.

<!-- Add docs/images/architecture.png and uncomment:
![Architecture](docs/images/architecture.png)
-->

## Repository layout

```
deploy/          docker-compose.yml + .env.example — the full stack
wazuh/           custom detection rules (local_rules.xml)
sysmon/          Sysmon configuration used on endpoints
n8n/             workflow.json (23 nodes) + code-nodes/ (extracted JavaScript)
docs/            thesis and technical documentation (Arabic)
results/         performance measurements
```

The n8n Code nodes are also extracted to `n8n/code-nodes/` as standalone `.js` files so the
IOC extraction and payload-building logic can be read without importing the workflow.

## Detection rules

`wazuh/local_rules.xml` contains custom rules for IOC-bearing endpoint activity:

| Rule ID | Detects | MITRE |
|---|---|---|
| 100010 | PowerShell outbound network connection (Sysmon Event 3) | T1059.001, T1043 |
| 100308 | `Invoke-WebRequest` to a raw IP | — |
| 100300 / 100303 | IP literal in `ping` / `tracert` command line | — |
| 100305 / 100316 | IP or URL in a `curl` command line | — |
| 100302 | Domain in a DNS query (Sysmon Event 22) | — |
| 100309 | `nslookup` invocation | — |
| 100420 | `certutil -urlcache` download | T1105 |

## Results

Each scenario was executed 10 times. Times in seconds.

| Scenario | IOC type | MTTD (avg) | MTTR (avg) | Success |
|---|---|---|---|---|
| PowerShell script execution | URL | 4.02 | 10.79 | 10/10 |
| TCP connection to suspicious IP | IP + domain | 6.26 | 11.67 | 10/10 |
| DNS query to malicious domain | Domain | 6.09 | 14.85 | 10/10 |
| File integrity monitoring | Hash | 3.28 | 19.04 | 10/10 |

Detection is fastest for file-integrity events and slowest for network events. Response time is
dominated by the external analyser, not the architecture — the 40.50 s outlier in the hash
scenario is VirusTotal free-tier rate limiting.

## Getting started

Requires Docker and Docker Compose, ~20 GB RAM for the full stack, and a Wazuh server.

```bash
git clone https://github.com/altahirsalimit/Open-Source-SOC-Automation-Framework-for-IOC-driven-Incident-Response
cd Open-Source-SOC-Automation-Framework-for-IOC-driven-Incident-Response/deploy
cp .env.example .env        # then edit: set HOST_IP and generate real secrets
docker compose up -d
```

Then:

1. Install Wazuh agents and Sysmon on your endpoints, using `sysmon/sysmonconfig.xml`.
2. Append `wazuh/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` and restart the manager.
3. Point the Wazuh integration at the n8n webhook.
4. Import `n8n/workflow.json` into n8n and set MISP, TheHive and Cortex credentials.
5. Enable the VirusTotal, AbuseIPDB and OTX analysers in Cortex with your own API keys.
6. Subscribe MISP to threat feeds (Malware Bazaar, ThreatFox, URLhaus).

**This is a lab framework.** Default credentials and open ports are for an isolated environment;
harden everything before running it anywhere reachable.

## Scope and limitations

Automated: detection, triage, IOC extraction, enrichment, case creation.
Not automated: containment, eradication, recovery — these stay under human control by design.

Tested only in an isolated virtual environment against four scripted scenarios, with IOC-based
detection only (no behavioural analysis). Manual-processing baselines are taken from the
literature, not from a parallel measured control group.

## Documentation

- `docs/thesis-ar.pdf` — full thesis (Arabic, with English abstract)

## Built with

[Wazuh](https://wazuh.com) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) ·
[n8n](https://n8n.io) · [TheHive](https://strangebee.com) · [Cortex](https://github.com/TheHive-Project/Cortex) ·
[MISP](https://www.misp-project.org) · [Docker](https://www.docker.com)

Enrichment sources: VirusTotal, AbuseIPDB, AlienVault OTX.

## Authors

Altahir Hassan Altahir Salim · Mohsen Taher Iseidyah 
· Supervisor: Salwa Abdulnabi — Sabha University

## License

MIT — see [LICENSE](LICENSE).
