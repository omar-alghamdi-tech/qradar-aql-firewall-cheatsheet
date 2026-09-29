#  AQL Reference for Firewall Log Analysis in IBM QRadar

📥 [Download the original Cheat Sheet (PDF) here](1750675704325.pdf)

##  Overview
This cheat sheet provides a comprehensive collection of ready-to-use Ariel Query Language (AQL) queries designed for IBM QRadar. It assists Security Operations Center (SOC) analysts and cybersecurity professionals in accelerating the detection, investigation, and hunting of security incidents through firewall log analysis.

##  AQL Query Cheat Sheet

### 1. Top Blocked Source IPs
Identifies the most frequently blocked or denied source IP addresses.
```sql
SELECT sourceIP, COUNT(*) AS attempts
FROM events
WHERE logsourceid = 71
AND (LOWER(action) = 'deny' OR LOWER(action) = 'block')
GROUP BY sourceIP
ORDER BY attempts DESC
LAST 7 DAYS
```

### 2. Unusual Destination Ports
Analyzes network connections targeting uncommon or non-standard destination ports.
```sql
SELECT destinationPort, destinationIP, COUNT(*) AS count
FROM events
WHERE logsourceid = 71
AND destinationPort NOT IN (80, 443, 22, 53, 25, 21)
GROUP BY destinationPort, destinationIP
ORDER BY count DESC
LAST 7 DAYS
```

### 3. Port Scanning Detection
Detects potential port scanning activities by identifying source IPs accessing a high number of unique destination ports.
```sql
SELECT sourceIP, COUNT(DISTINCT destinationPort) AS unique_ports
FROM events
WHERE logsourceid = 71
GROUP BY sourceIP
HAVING unique_ports > 15
ORDER BY unique_ports DESC
LAST 7 DAYS
```

### 4. Outbound Connection Spikes
Monitors and highlights abnormal spikes in outbound network traffic volume. *(Note: QRadar uses `bucket` for time aggregation instead of `_time` like Splunk)*.
```sql
SELECT sourceIP, START(bucket) AS time, COUNT(*) AS count
FROM events
WHERE logsourceid = 71
AND direction = 'outbound'
GROUP BY sourceIP, bucket START '2025-06-15 00:00:00' STOP '2025-06-22 00:00:00' EVERY 1 HOUR
HAVING count > 1000
ORDER BY time DESC
```

### 5. High-Risk Connections
Displays connections associated with high-risk or critical threat indicators. *(Note: Replace `category` with `threatName` or `eventCategory` based on available logs)*.
```sql
SELECT sourceIP, category, COUNT(*) AS count
FROM events
WHERE logsourceid = 71
AND (severity = 'High' OR severity = 'Critical')
GROUP BY sourceIP, category
ORDER BY count DESC
LAST 7 DAYS
```

### 6. After-Hours VPN Connections
Detects VPN access occurring outside of standard business hours. *(Ensure `username` and `startTime` fields are parsed)*.
```sql
SELECT sourceIP, username, HOUR(startTime) AS hour, COUNT(*) AS count
FROM events
WHERE logsourceid = 71
AND LOWER(category) LIKE '%vpn%'
AND (HOUR(startTime) >= 22 OR HOUR(startTime) <= 5)
GROUP BY sourceIP, username, hour
ORDER BY count DESC
LAST 7 DAYS
```

### 7. Geographically Unusual Access
Highlights allowed inbound connections originating from unexpected or unusual geographical locations. *(Requires GeoIP integration in QRadar)*.
```sql
SELECT sourceIP, geoCountry AS country, COUNT(*) AS count
FROM events
WHERE logsourceid = 71
AND LOWER(action) = 'allow'
AND geoCountry NOT IN ('Saudi Arabia')
GROUP BY sourceIP, country
ORDER BY count DESC
LAST 7 DAYS
```

### 8. Authentication Failure Patterns
Analyzes repeated authentication failures to identify potential brute-force or credential stuffing attacks.
```sql
SELECT sourceIP, username, COUNT(*) AS failures
FROM events
WHERE logsourceid = 71
AND LOWER(eventCategory) = 'authentication'
AND LOWER(status) = 'failure'
GROUP BY sourceIP, username
HAVING failures > 5
ORDER BY failures DESC
LAST 7 DAYS
```

### 9. Traffic to Malicious Domains
Correlates network traffic with known threat intelligence indicators (e.g., Malware or C2 servers). *(Relies on Threat Intelligence feeds like IBM X-Force or MISP)*.
```sql
SELECT sourceIP, destinationHostname, threatCategory, COUNT(*) AS hits
FROM events
WHERE logsourceid = 71
AND (LOWER(threatCategory) = 'malware' OR LOWER(threatCategory) = 'c2')
GROUP BY sourceIP, destinationHostname, threatCategory
ORDER BY hits DESC
LAST 7 DAYS
```

---
**General Implementation Notes:**
* **Log Source ID:** Verify and update `logsourceid = 71` to match the specific firewall log source ID in your QRadar environment.
* **Timeframe:** Queries utilize `LAST 7 DAYS` as a default timeframe, which can be adjusted as needed.
* **Field Parsing:** Field names such as `action`, `destinationPort`, and `sourceIP` may vary based on the specific device type (DSM) or log format.
