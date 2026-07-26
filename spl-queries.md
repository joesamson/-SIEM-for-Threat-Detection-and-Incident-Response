# 🔍 Splunk Detection Rules (SPL Queries)



---

## 1. Windows Failed Login Brute Force

```spl
index=windows_logs EventCode=4625
| stats count AS failed_attempts by Account_Name, src_ip
| where failed_attempts > 5
| sort - failed_attempts
```

---

## 2. Successful Login After Multiple Failures

```spl
index=windows_logs EventCode IN (4624,4625)
| stats
    count(eval(EventCode=4625)) AS failed_logins,
    count(eval(EventCode=4624)) AS successful_logins
    by Account_Name, src_ip
| where failed_logins > 5 AND successful_logins > 0
```

---

## 3. Password Spraying Detection

```spl
index=botsv2 EventCode=4625
| stats dc(user) AS targeted_users by src_ip
| where targeted_users > 5
```

---

## 4. Account Lockout Detection

```spl
index=botsv2 EventCode=4740
| stats count by user, src_ip, host
```

---

## 5. Successful RDP Login

```spl
index=botsv2 EventCode=4624 Logon_Type=10
| table _time user src_ip host
```

---

## 6. Failed RDP Login Attempts

```spl
index=botsv2 EventCode=4625 Logon_Type=10
| stats count by src_ip,user
| where count > 5
```

---

## 7. Unusual Login Time (After-Hours Access)

```spl
index=botsv2 (EventCode=4624 OR action=success)
| eval login_hour=strftime(_time,"%H")
| where login_hour>=0 AND login_hour<=6
| stats count by user,src_ip,host
```

---

## 8. Multiple Authentication Attempts Across Users

```spl
index=botsv2 EventCode=4625
| stats dc(user) AS targeted_users by src_ip
| where targeted_users > 5
```

---

## 9. Impossible Travel Login Detection

```spl
index=botsv2 EventCode=4624
| iplocation src_ip
| stats values(Country) AS countries by user
| where mvcount(countries) > 1
```

---

## 10. Multiple Source IP Logins

```spl
index=botsv2 EventCode=4624
| stats dc(src_ip) AS ip_count by user
| where ip_count > 5
```

---

## 11. Horizontal Port Scan

```spl
index=network_logs
| stats dc(dest_ip) AS hosts by src_ip
| where hosts > 20
```

---

## 12. Vertical Port Scan

```spl
index=network_logs
| stats dc(dest_port) AS ports by src_ip,dest_ip
| where ports > 20
```

---

## 13. Multiple Port Access Detection

```spl
index=network_logs
| stats dc(dest_port) AS unique_ports by src_ip
| where unique_ports > 10
```

---

## 14. High Connection Attempts

```spl
index=network_logs
| bin _time span=1m
| stats count by src_ip,_time
| where count > 50
```

---

## 15. Network Scanning Detection

```spl
index=network_logs
| stats count dc(dest_port) AS ports by src_ip
| where ports > 15
```

---

## 16. High Traffic Volume Detection

```spl
index=network_logs
| stats count AS packet_count by src_ip
| where packet_count > 1000
```

---

## 17. Time-Based DoS Detection

```spl
index=network_logs
| bin _time span=30s
| stats count by src_ip,_time
| where count > 500
```

---

## 18. PowerShell Execution

```spl
index=botsv2 process_name="powershell.exe"
| table _time user command_line
```

---

## 19. Encoded PowerShell Commands

```spl
index=botsv2 process_name="powershell.exe" command_line="*EncodedCommand*"
```

---

## 20. PowerShell Download Cradle

```spl
index=botsv2 process_name="powershell.exe"
(command_line="*DownloadString*" OR command_line="*Invoke-WebRequest*")
```

---

## 21. Suspicious CMD Execution

```spl
index=botsv2 process_name="cmd.exe"
| table _time user command_line
```

---

## 22. Office Spawning PowerShell

```spl
index=botsv2
parent_process IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE")
process_name="powershell.exe"
```

---

## 23. Scheduled Task Creation

```spl
index=botsv2 EventCode=4698
```

---

## 24. Service Installation Detection

```spl
index=botsv2 EventCode=4697
```

---

## 25. Registry Run Key Persistence

```spl
index=botsv2 registry_path="*CurrentVersion\\Run*"
```

---

## 26. New User Account Creation

```spl
index=botsv2 EventCode=4720
```

---

## 27. Administrator Group Modification

```spl
index=botsv2 EventCode=4732
| search Group_Name="Administrators"
```

---

## 28. Privilege Escalation Detection

```spl
index=botsv2 EventCode IN (4672,4673,4674)
```

---

## 29. Linux Sudo Abuse

```spl
index=linux_log sourcetype=linux_audit*
| search command="sudo*"
```

---

## 30. Mimikatz Detection

```spl
index=botsv2
(command_line="*mimikatz*" OR command_line="*sekurlsa*")
```

---

## 31. LSASS Credential Dumping

```spl
index=botsv2
process_name="procdump.exe"
OR command_line="*lsass*"
```

---

## 32. Pass-the-Hash Detection

```spl
index=botsv2 EventCode=4624 Logon_Process="NtLmSsp"
```

---

## 33. PsExec Lateral Movement

```spl
index=botsv2
(command_line="*psexec*" OR Service_Name="PSEXESVC")
```

---

## 34. WMI Remote Execution

```spl
index=botsv2 process_name="wmic.exe"
```

---

## 35. Port Scan and Brute Force Correlation

```spl
index=windows_logs
| stats
    dc(dest_port) AS scanned_ports,
    count(eval(EventCode=4625)) AS failed_logins
    by src_ip
| where scanned_ports > 10 AND failed_logins > 5
```

---

