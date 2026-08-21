# Performance measurements

Isolated lab environment. Each scenario executed 10 times.

- **MTTD** — from execution of the activity on the endpoint to alert creation in TheHive.
- **MTTR** — from alert creation in TheHive to completion of Cortex enrichment.

Execution timestamps were recorded manually to account for the 1–3 s delay between the activity
and Sysmon writing the event; MTTR was read from the n8n workflow execution time.

| Scenario | IOC | MTTD avg | MTTD range | MTTR avg | MTTR range | Success |
|---|---|---|---|---|---|---|
| PowerShell script execution | URL | 4.02 | 3.49 – 4.61 | 10.79 | 9.89 – 13.95 | 10/10 |
| TCP connection to suspicious IP | IP + domain | 6.26 | 4.98 – 7.51 | 11.67 | 10.20 – 20.75 | 10/10 |
| DNS query to malicious domain | Domain | 6.09 | 4.91 – 6.74 | 14.85 | 10.90 – 20.63 | 10/10 |
| File integrity monitoring | Hash | 3.28 | 2.50 – 3.98 | 19.04 | 10.83 – 40.50 | 10/10 |

All times in seconds.

## Notes

Detection and response are independent. The FIM scenario has the fastest detection (Syscheck
catches file changes immediately) and the slowest response (VirusTotal queries dozens of AV
engines and rate-limits free accounts) — the two metrics are governed by different components.

Network events (TCP, DNS) detect more slowly than process-creation and file events, reflecting
how Sysmon records Event ID 3 and 22.

The widest response ranges (~10 s spread) come from variability in the external enrichment
services, not from the workflow. The single 40.50 s outlier was VirusTotal rate limiting.
