# Investigate a Suspicious File Hash

<h2>Description</h2>
As a Level One analyst within a financial services firm's Security Operations Center (SOC), you've recently been alerted to a concerning incident. This incident involves the download of a suspicious file onto an employee's workstation.

Upon receiving the alert, you've taken on the responsibility of delving into the matter. Your investigation has unveiled that the employee in question received an email containing an attachment. The attachment took the form of a password-protected spreadsheet, with the password conveniently supplied within the same email. The employee proceeded to download this file and utilized the provided password to unlock its contents. Regrettably, upon accessing the file, a malevolent payload was activated on the employee's computer.

As part of your actions, you've successfully recovered the malicious file itself. In addition, you've generated a SHA256 hash value for this file. Drawing from your prior knowledge, which you gained through a previous course, you understand that a hash function operates as an algorithm producing an encrypted code that remains impervious to decryption. This cryptographic technique of hashing is indispensable for establishing a distinct identity for malware, akin to a one-of-a-kind digital fingerprint for each file.

<h2> Alert Description</h2>

SHA256 file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Here is a timeline of the events leading up to this alert:

- <b>1:11 p.m.: An employee receives an email containing a file attachment.</b>

- <b>1:13 p.m.: The employee successfully downloads and opens the file.</b>

- <b>1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.</b>

- <b>1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.</b>

<h2>I decided to use VirusTotal to analyze the malicious file</h2>
I entered the SHA256 file hash in the search box to determine that the file hash has been reported as malicious by 58 vendors and 2 sandboxes reports. 

![Screenshot 2024-12-30](https://github.com/jalphonseportfolio/Investigate-a-Suspicious-File-Hash/blob/main/pic01.png)


<h2> Pain Pyramid</h2>

![Screenshot 2024-12-30](https://github.com/jalphonseportfolio/Investigate-a-Suspicious-File-Hash/blob/main/pic02.png)

<h2>Incident Handler's Report</h2>

![Screenshot 2024-12-30](https://github.com/jalphonseportfolio/Investigate-a-Suspicious-File-Hash/blob/main/pic03.png)

<h2> </h2>
After investigating the email attachment file's hash, the attachment has already been verified maliciously. Now that you have this information, you must follow your organization's process to complete your investigation and resolve the alert.

<h2>Use a playbook to respond to a phishing incident</h2>
Physing Flowchart is provided by the Financial Services Firm. The flowchart is part of the playbook which is considered the manual or step-by-step process to respond to certain incidents. 

![Screenshot 2024-12-30](https://github.com/jalphonseportfolio/Investigate-a-Suspicious-File-Hash/blob/main/pic04.png)

<h2>Completed Alert Ticket</h2>

![Screenshot 2024-12-30](https://github.com/jalphonseportfolio/Investigate-a-Suspicious-File-Hash/blob/main/pic05.png)


![Screenshot 2024-12-30](https://github.com/jalphonseportfolio/Investigate-a-Suspicious-File-Hash/blob/main/pic06.png)

<h2>Summary</h2>
Following an alert about a suspicious file downloaded onto an employee's workstation, I conducted a comprehensive investigation. The incident involved an employee receiving an email with a password-protected spreadsheet attachment. Upon opening the spreadsheet, unauthorized executable files were activated on the employee's computer. To determine the nature of the threat, I generated the SHA256 hash value of the malicious file and submitted it for analysis on VirusTotal. This analysis confirmed that the file had been flagged as malicious by multiple security vendors and sandboxes. In accordance with our organization's phishing incident playbook, I documented the incident, resolved the immediate alert, and implemented measures to safeguard our systems. This incident serves as a critical reminder of the importance of robust cybersecurity measures and ongoing vigilance to effectively mitigate the risks associated with malicious actors.
