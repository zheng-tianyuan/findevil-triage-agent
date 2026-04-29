# Dataset Documentation

## Case

`data/case-001` is a synthetic Linux incident-response case.

## Artifacts

- `auth.log`: SSH failures followed by an accepted password from the same source IP.
- `processes.json`: process snapshot containing a suspicious curl-to-shell command.
- `network.json`: network snapshot containing an outbound connection on port 8081.
- `crontab.txt`: synthetic scheduled task using `/tmp`.
- `file_timeline.csv`: selected file creation/modification timeline entries.
- `dns.log`: DNS lookup around payload staging time.

## Ground Truth

Expected supported findings:

- Repeated SSH failures from `203.0.113.77`.
- Failed logins followed by a successful login from `203.0.113.77`.
- Suspicious command line for PID `1410`.
- Unusual outbound connection to `198.51.100.24:8081`.
- Suspicious scheduled task.
- Cron artifact changed.
- Suspicious DNS lookup.
- Process-to-network correlation for PID `1410`.

Expected self-correction:

- The injected “Possible malware persistence” candidate should be removed because no persistence artifact exists in the dataset.
