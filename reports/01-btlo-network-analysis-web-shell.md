# Incident Report: Port Scan to Web Shell and Reverse Shell on bob-appserver

|||
|-|-|
|**Source**|Blue Team Labs Online|
|**Challenge / Exercise**|Network Analysis – Web Shell (retired challenge, Easy, Security Operations)|
|**Evidence**|`BTLOPortScan.pcap` (17,508 packets, captured 2021-02-07)|
|**Date investigated**|2026-10-04|
|**Analyst**|Gurpreet Singh Saini|
|**Severity**|High|
|**Tools used**|Wireshark (Conversations, display filters, Follow HTTP/TCP Stream) in an isolated Ubuntu VM with no network access|

## 1\. Executive Summary

The SIEM alert for "Local to Local Port Scanning" was **a true positive, and the activity was malicious**. Internal host `10.251.96.4` scanned ports 1 to 1024 on the web server `10.251.96.5` (hostname `bob-appserver`), then enumerated hidden web paths with gobuster and tested the site with sqlmap. The attacker then abused an unrestricted file upload to plant a PHP web shell named `dbfunctions.php` and used it to start a Python reverse shell back to `10.251.96.4` on port 4422. In the part of the live session I reviewed, the attacker ran as the low-privilege `www-data` account and explored the filesystem. The web server should be treated as compromised, isolated, and rebuilt, and the upload function must be fixed.

## 2\. Scenario

The SOC received an alert in their SIEM for "Local to Local Port Scanning", where an internal private IP began scanning another internal system. A PCAP was provided, and the task was to determine whether the activity was malicious.

## 3\. Investigation Timeline

All times are UTC and all events took place on 2021-02-07. Times come from packet timestamps unless noted.

|Time (UTC)|Event|Evidence|
|-|-|-|
|16:33:06|`10.251.96.4` begins a TCP SYN scan of `10.251.96.5`, ports 1 to 1024, from source port 41675|`webshell-03`, `webshell-06`, `webshell-07`|
|16:33:06|Scan finds ports 80 and 22 open (SYN-ACK replies). On port 80 the scanner answers with RST instead of ACK, which is the signature of a half-open SYN scan|`webshell-04`, `webshell-05`|
|16:33:31|Manual browsing of the web site begins: `/`, `/login.php` (including a form POST), `/info.php`, `/index.php`, `/uploads/`, `/server-status`|`webshell-08`|
|16:34:05|gobuster/3.0.1 starts guessing page and folder names (thousands of requests milliseconds apart)|`webshell-09`|
|Before 16:40:45 (exact time not recorded)|sqlmap/1.4.7 sends 147 requests, including a `UNION ALL` injection string, against the site|`webshell-10`|
|16:40:39|Web shell `dbfunctions.php` uploaded from the page `editprofile.php` through `upload.php`. Server replies `200 OK`: "The file dbfunctions.php has been uploaded."|`webshell-11`, `webshell-12`|
|16:40:43|Attacker requests `/uploads/` (checking the file landed)|`webshell-12`|
|16:40:45|First request to `/uploads/dbfunctions.php` with no command (testing the shell)|`webshell-13`|
|16:40:51|**First command executed:** `cmd=id`|`webshell-13`|
|16:40:56|`cmd=whoami`|`webshell-13`|
|16:42:35|`cmd=python -c '...'` launches a Python reverse shell (packet 16201)|`webshell-13`|
|16:42:35|`bob-appserver` (`10.251.96.5`) connects out to `10.251.96.4:4422`. Interactive session begins (348 packets on port 4422)|`webshell-15`|
|From 16:42:35|Attacker runs `bash -i`, `whoami`, `cd`, `ls`, and a Python `pty.spawn` shell upgrade, then lists the root directory|`webshell-16`|

## 4\. Technical Analysis

### 4.1 Identifying the scanner

Statistics → Conversations showed one pair of hosts dominating the capture: `10.251.96.4` ↔ `10.251.96.5` with 15,883 of the 17,508 packets. On the TCP tab there were 1,284 conversations, most of them exactly two packets long, always from source port 41675 to a different destination port each time. That pattern of "one knock, one reply, move on" is how a port scan looks.

!\[IPv4 conversations   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-01-ipv4-conversations.png)
!\[TCP conversations   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-02-tcp-conversations.png)

### 4.2 Scan type and range

Filtering for SYN-only packets from the suspect (`ip.src == 10.251.96.4 \&\& tcp.flags.syn == 1 \&\& tcp.flags.ack == 0`) showed the scan knocking on ports in rapid succession. Restricting to the scan's source port and sorting the Conversations window by destination port gave a lowest port of **1** and a highest of **1024**, a total of 1,024 ports.

!\[SYN scan filter   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-03-syn-scan-filter.png)
!\[Lowest port   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-06-lowest-port.png)
!\[Highest port   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-07-highest-port.png)

Filtering for SYN-ACK replies from the target (`ip.src == 10.251.96.5 \&\& tcp.flags.syn == 1 \&\& tcp.flags.ack == 1`) showed ports **80** and **22** responding to the scanner.

!\[Open ports   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-04-open-ports.png)

Following the exchange on port 80 (`tcp.port == 41675 \&\& tcp.port == 80`) shows SYN, then SYN-ACK from the target, then **RST** from the scanner. The scanner never completes the handshake, so this is a **TCP SYN (half-open) scan**. The window size of 1024 is commonly associated with Nmap, but the capture alone does not prove which tool was used.

!\[SYN, SYN-ACK, RST handshake   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-05-handshake-port80.png)

### 4.3 Web enumeration and injection testing

Filtering for the suspect's HTTP requests (`http.request \&\& ip.src == 10.251.96.4`) returned 4,794 requests. Only 32 carried a browser User-Agent (Firefox 68.0 on Linux) and looked like manual browsing. Excluding Firefox left 4,762 requests, nearly all with the User-Agent **gobuster/3.0.1**, which guesses hidden paths from a word list. Excluding gobuster as well left 147 requests with the User-Agent **sqlmap/1.4.7#stable**, including a POST with a `UNION ALL` SQL injection payload.

!\[Browser User-Agent   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-08-user-agents.png)
!\[gobuster requests   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-09-non-browser-agents.png)
!\[sqlmap requests   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-10-remaining-tools.png)

I did not determine whether the sqlmap testing succeeded.

### 4.4 Malicious file upload

A Follow HTTP Stream on the upload request shows a `multipart/form-data` POST to `/upload.php` with `Referer: http://10.251.96.5/editprofile.php`. So the attacker used the profile-picture upload form on `editprofile.php`, which is processed by `upload.php`. The uploaded file is named **`dbfunctions.php`** and is sent as `Content-Type: application/x-php`. The server accepted it with `200 OK` and the message "The file dbfunctions.php has been uploaded." The request carried a PHP session cookie, but this capture does not show how that session was obtained.

!\[Upload stream   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-11-upload-stream.png)
!\[Upload response   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-12-upload-response.png)

### 4.5 The web shell

The uploaded file is a few lines of PHP. If a request includes a parameter named `cmd`, the script passes its value to PHP's `system()` function, prints the output, and stops. The code is visible in the upload stream screenshot above (`webshell-11`) and is intentionally not reproduced here.

Any request to `/uploads/dbfunctions.php?cmd=<command>` makes the server run `<command>` and print the output. The command parameter is **`cmd`**. The file name was chosen to look like a normal database helper.

### 4.6 Command execution and reverse shell

Filtering for requests to the shell (`http.request.uri contains "dbfunctions.php" \&\& ip.src == 10.251.96.4`) shows four requests, in time order: the bare file request, `cmd=id` (the **first command executed**), `cmd=whoami`, and a long `cmd=python -c '...'`. The last one (packet 16201, URL encoding removed) is a Python one-liner that:

* opens a TCP socket and connects to `10.251.96.4` on port `4422`
* attaches the socket to the shell's standard input, output and error
* starts an interactive `/bin/sh`

This is a **reverse shell**. The full command is visible in the screenshot below.

!\[Shell commands   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-13-shell-commands.png)

About 70 milliseconds later, the web server (`10.251.96.5`) opens a TCP connection **out to `10.251.96.4` on port 4422** (SYN, then SYN-ACK). The victim initiated the connection, which is what makes it a **reverse shell**. Port 4422 is not a standard service port.

!\[Reverse shell connection   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-15-reverse-shell-connection.png)

### 4.7 Attacker activity in the shell

Following the TCP stream for port 4422 shows the attacker's session. The prompt reveals the host name **`bob-appserver`**, the user **`www-data`**, and the starting folder `/var/www/html/uploads`. The attacker ran `bash -i`, `whoami`, moved up the directory tree with `cd ..`, ran `ls`, upgraded the terminal with a Python `pty.spawn` call, and listed the root of the filesystem.

!\[Shell session   ](https://raw.githubusercontent.com/me-gurpreetsaini/incident-investigation-writeups/main/images/webshell-16-shell-session.png)

## 5\. Indicators of Compromise (IOCs)

|Type|Value|Context|
|-|-|-|
|IP address|`10.251.96.4`|Attacker host: port scan, gobuster, sqlmap, upload, reverse shell listener|
|IP address|`10.251.96.5` (`bob-appserver`)|Victim web server (Apache/2.4.29, Ubuntu)|
|TCP port|4422|Reverse shell connection, victim to attacker|
|TCP source port|41675|Source port used by the SYN scan|
|User-Agent|`gobuster/3.0.1`|Directory and file enumeration|
|User-Agent|`sqlmap/1.4.7#stable`|SQL injection testing|
|File|`/uploads/dbfunctions.php`|Web shell|
|URL pattern|`/uploads/dbfunctions.php?cmd=`|Web shell command execution|
|URLs|`/editprofile.php`, `/upload.php`|Upload form and upload handler abused|
|Command|Python one-liner using socket, subprocess and os that connects to `10.251.96.4:4422`|Reverse shell launcher|
|Session cookie|`PHPSESSID=10b3rrv35ctuvv7vlnsfr6ugjt`|Session used for the upload and shell requests|
|File hash (SHA256)|Not available|The shell was read from network traffic only and not extracted from disk|

## 6\. Root Cause

The profile-picture upload function accepted a PHP script (`application/x-php`) and stored it in `/uploads/`, a folder that is reachable from the web and executes PHP. There was no check on file type or content and no restriction on execution in that folder. This turned a legitimate feature into remote code execution. How the attacker obtained the session used for the upload, and whether the sqlmap testing contributed, is not established by this capture.

## 7\. MITRE ATT\&CK Mapping

|Tactic|Technique|ID|Evidence|
|-|-|-|-|
|Discovery|Network Service Discovery|T1046|SYN scan of ports 1 to 1024|
|Reconnaissance|Active Scanning: Wordlist Scanning|T1595.003|gobuster/3.0.1 requests|
|Initial Access|Exploit Public-Facing Application|T1190|Unrestricted file upload (sqlmap injection testing attempted)|
|Persistence|Server Software Component: Web Shell|T1505.003|`dbfunctions.php`|
|Execution|Command and Scripting Interpreter: Unix Shell|T1059.004|`bash -i`, `/bin/sh -i`|
|Execution|Command and Scripting Interpreter: Python|T1059.006|`python -c` reverse shell|
|Command and Control|Non-Standard Port|T1571|Reverse shell on TCP 4422|
|Discovery|System Owner/User Discovery|T1033|`id`, `whoami`|
|Discovery|File and Directory Discovery|T1083|`ls`, `cd`|

## 8\. Recommendations

**Immediate actions (containment)**

* Isolate `bob-appserver` (`10.251.96.5`) from the network and preserve a disk image for forensics.
* Block and investigate `10.251.96.4`. Determine who owns it and how it was compromised or misused.
* Remove `/uploads/dbfunctions.php` and search the uploads folder and the rest of the web root for other unexpected PHP files.
* Invalidate active sessions, rotate any credentials stored on or reachable from the web server, and review the database for signs of data access through the SQL injection testing.
* Because an attacker had a shell on the host, rebuild the server from a known-good image rather than cleaning it in place.

**Long-term improvements**

* Restrict uploads to an allowlist of image types, validate content and not only the extension or declared type, and rename files on save.
* Store uploads outside the web root, or disable script execution in the uploads folder.
* Use parameterized queries and review the login and profile code paths for SQL injection.
* Filter outbound traffic from web servers so a server cannot freely open connections to arbitrary hosts and ports such as 4422.
* Add SIEM detections for: multipart uploads of `.php` files, requests to files in upload folders with a command-like parameter, the web server process spawning `sh`, `bash` or `python`, and outbound connections from the web server to internal hosts on unusual ports.
* Segment the network so that one internal host cannot scan servers freely, and alert on bursts of connection attempts across many ports.

## 9\. Lessons Learned

* Working through the PCAP in layers (who talks the most, then what protocol, then what tool, then what happened next) made each step easy to prove with a filter and a screenshot.
* The same upload involved two files: `editprofile.php` hosts the form and `upload.php` processes it. The Referer header is what links them, so reading the full HTTP stream matters more than the first line.
* A one-digit typo in an IP address filter (`10.254.96.4` instead of `10.251.96.4`) returned zero packets. Checking the filter before assuming the data is empty saved time.
* Limits of this write-up: I did not review the whole 4422 session after the first screens, so later attacker actions may exist. The exact start of the sqlmap activity was not recorded, and I did not extract any file from the capture for hashing.
* All analysis was done in an isolated VM with networking disabled, as the PCAP comes from real malicious traffic.

\---

*Published as a write-up of a retired Blue Team Labs Online challenge.*

