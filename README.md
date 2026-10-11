
#  AQL Reference for Firewall Log Analysis in IBM QRadar

[qradar-aql-firewall-cheatsheet.pdf.pdf](https://github.com/user-attachments/files/33313700/qradar-aql-firewall-cheatsheet.pdf.pdf)

##  Overview

A collection of ready-to-use **Ariel Query Language (AQL)** queries for IBM QRadar, built to help SOC analysts speed up detection, investigation, and threat hunting through firewall log analysis.

All queries use **native QRadar fields and functions** (e.g. `CATEGORYNAME()`, `eventdirection`, `GEO::LOOKUP()`, `REFERENCESETCONTAINS()`), so they work without relying on custom properties unless noted.

##  Before You Start

Replace `'FW-01'` in every query with your firewall's log source name. To list your log sources:

```sql
SELECT LOGSOURCENAME(logsourceid) AS log_source, COUNT(*) AS events
FROM events
GROUP BY logsourceid
ORDER BY events DESC
LAST 24 HOURS
```

> Filtering by log source **name** instead of a hard-coded `logsourceid` makes the queries portable and easier to read.

---

##  Query Cheat Sheet

### 1. Top Blocked Source IPs
Most frequently denied source IPs — a quick view of who is knocking on your perimeter.

```sql
SELECT sourceip, COUNT(*) AS attempts
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
  AND CATEGORYNAME(category) = 'Firewall Deny'
GROUP BY sourceip
ORDER BY attempts DESC
LAST 7 DAYS
```

### 2. Unusual Destination Ports (Outbound)
Allowed outbound connections to non-standard ports — possible C2, tunneling, or shadow IT.

```sql
SELECT sourceip, destinationip, destinationport, COUNT(*) AS connections
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
  AND CATEGORYNAME(category) = 'Firewall Permit'
  AND eventdirection = 'L2R'
  AND destinationport NOT IN (80, 443, 22, 53, 25, 21)
GROUP BY sourceip, destinationip, destinationport
ORDER BY connections DESC
LAST 7 DAYS
```

### 3. Port Scanning Detection
Sources hitting a high number of distinct destination ports.

```sql
SELECT sourceip, UNIQUECOUNT(destinationport) AS unique_ports, COUNT(*) AS attempts
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
GROUP BY sourceip
HAVING UNIQUECOUNT(destinationport) > 15
ORDER BY unique_ports DESC
LAST 24 HOURS
```

### 4. Outbound Connection Spikes (Hourly)
Internal hosts generating an abnormal volume of outbound connections per hour.

```sql
SELECT sourceip, DATEFORMAT(starttime, 'yyyy-MM-dd HH:00') AS hour_bucket, COUNT(*) AS connections
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
  AND eventdirection = 'L2R'
GROUP BY sourceip, hour_bucket
HAVING COUNT(*) > 1000
ORDER BY connections DESC
LAST 7 DAYS
```

> `eventdirection` values: `L2R` (local → remote), `R2L` (remote → local), `L2L`, `R2R`.

### 5. High-Severity Events
Events QRadar rates as high severity. `severity` is numeric (0–10), not text.

```sql
SELECT sourceip, CATEGORYNAME(category) AS category_name, MAX(severity) AS max_severity, COUNT(*) AS events
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
  AND severity >= 7
GROUP BY sourceip, category
ORDER BY events DESC
LAST 7 DAYS
```

### 6. After-Hours VPN Logins
Successful VPN logins outside business hours (22:00–05:59).

```sql
SELECT username, sourceip, DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm') AS login_time
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'VPN-01'
  AND CATEGORYNAME(category) ILIKE '%login succe%'
  AND DATEFORMAT(starttime, 'HH') IN ('22','23','00','01','02','03','04','05')
ORDER BY starttime DESC
LAST 7 DAYS
```

> `DATEFORMAT` follows the QRadar console time zone — adjust the hour list if your users work in a different zone.

### 7. Inbound Allowed Traffic from Unexpected Countries
Allowed inbound connections from outside your expected geography.

```sql
SELECT sourceip, GEO::LOOKUP(sourceip, 'country') AS country, destinationport, COUNT(*) AS connections
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
  AND CATEGORYNAME(category) = 'Firewall Permit'
  AND eventdirection = 'R2L'
  AND GEO::LOOKUP(sourceip, 'country') <> 'Saudi Arabia'
GROUP BY sourceip, destinationport
ORDER BY connections DESC
LAST 7 DAYS
```

### 8. Authentication Failure Patterns
Repeated login failures per user and source — brute-force or credential stuffing.

```sql
SELECT sourceip, username, COUNT(*) AS failures
FROM events
WHERE LOGSOURCENAME(logsourceid) IN ('FW-01', 'VPN-01')
  AND CATEGORYNAME(category) ILIKE '%login fail%'
GROUP BY sourceip, username
HAVING COUNT(*) > 5
ORDER BY failures DESC
LAST 24 HOURS
```

### 9. Traffic to Known Malicious IPs
Connections to IPs in a threat-intel reference set (populated from X-Force, MISP, or your own IoC feed).

```sql
SELECT sourceip, destinationip, destinationport, COUNT(*) AS hits
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'FW-01'
  AND REFERENCESETCONTAINS('Malicious IPs', destinationip)
GROUP BY sourceip, destinationip, destinationport
ORDER BY hits DESC
LAST 7 DAYS
```

> Replace `'Malicious IPs'` with the name of your reference set.

---

##  Implementation Notes

- **Category names** (`Firewall Deny`, `Firewall Permit`, login success/failure) come from QRadar's normalized low-level categories, so they work across firewall vendors (DSMs).
- **Thresholds** (`> 15`, `> 1000`, `> 5`) are starting points — baseline your environment and tune them to reduce false positives.
- **Time windows** default to `LAST 7 DAYS` / `LAST 24 HOURS`; adjust as needed.
- **Performance:** always filter by log source and keep time windows tight on busy environments.

## 👤 Author

**Omar Alghamdi** — SOC Analyst | Threat Hunting
[LinkedIn](https://www.linkedin.com/in/omar-al-ghamdi-) · [X](https://x.com/Omar_Cyber7)
