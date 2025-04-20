![image](https://github.com/user-attachments/assets/64e9ab10-6ef1-4215-a2d2-26460e11dbd5)


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/art-wiju/Unauthorized-Tor-Usage/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string 'tor' in it and discovered that looks like the user "labus" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` in the `\ProgramData` folder. This is a hidden folder, so this is something quite suspicious. These events began at:
Query to locate events: `2025-04-19T04:01:59.7381591Z`



**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == 'windows-worksta'
| where FileName contains "tor"
| where Timestamp >= todatetime(('2025-04-19T04:01:59.7381591Z'))
| order by Timestamp Asc
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/4acabcd0-4a21-41c1-86bb-86da23f33748)

This only tells us that the files existed in this host, it doesn’t really tell us if the user executed the files or not. It is too early to tell. For this reason, I will check in the DeviceProcessEvents, which gives us information on processes (being launched, terminated, etc) on hosts. 

---

### 2. Searched the `DeviceProcessEvents` Table

I then searched the DeviceProcessEvents table for any signs of activity for any files containing the “tor” string. Based on logs returned, at `2025-04-19T04:04:14.0704242Z`, a user (or process) silently installed the Tor Browser on the machine `windows-workstation-1729` using a command prompt (CMD), without showing any prompts or windows (silent install), likely to avoid detection.

**Query used to locate event:**

```kql
Query to locate events:
DeviceProcessEvents
| where DeviceName == "windows-worksta"
| where ProcessCommandLine contains "tor"
| where Timestamp >= todatetime('2025-04-19T04:01:59.7381591Z')
| order by Timestamp Desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine, SHA256
```
![image](https://github.com/user-attachments/assets/f4528aed-aacb-4e3f-a630-5a1045d42343)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Further analyzing the same query, we can observe that there are many instances of a “firefox.exe” process being created (executed). However, we can deduce that this is nor a regular instance of Firefox, as TOR (The Onion Router) is a modified version of Firefox. Furthermore, we can see that the Initiating Folder contains “Tor Browser”.

At this point, we have enough evidence that the user installed and executed and instance of TOR browser at `2025-04-19T04:05:04.3097062Z`.

![image](https://github.com/user-attachments/assets/19aa67b0-8984-4493-adf9-5616379992ac)

When we check the SHA256 `3613fc46eab116864d28b7a3af1b7301fc0309bf3ba99c661a8c36ad5c848d02` in a website like VirusTotal, we can see that the hash matches to “Tor Browser”, specifically to a Windows Portable Executable. 

![image](https://github.com/user-attachments/assets/a1deb24d-0f10-4916-963b-8a9c12efe141)

![image](https://github.com/user-attachments/assets/66b43492-3c7f-4a85-a3b6-558278e97634)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

We now know that the user both installed and executed the TOR browser. The last piece of proof we need is whether the user actually used and navigated with it. I tried to query for the known TOR ports (even though technically any port could be used for TOR traffic), and I only received 1 result, so then I had to expand my search, just to find that random ports were being used. This is the query I used to investigate:

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-worksta"
| where InitiatingProcessFileName in~ ("tor.exe", "tor-browser.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 8443) // TOR ended up using different, random ports different from the expected.
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/ab5bbef5-d918-4aed-946a-cde0b856268e)

We can observe that there were several successful connections to different remote IPs originating from the “tor.exe” and “firefox.exe”. Some of these contained what looked like encrypted URLs. 

The first connection occurred at `2025-04-19T04:05:17.7449065Z` to `46.38.254.168` on port `40000` to the remote URL `https://www.3ohv4urbp74k3hgmewtx3bnka.com`. I tried accessing all 3 of these websites shown in the above screenshot directly from my browser and I immediately received an error that these websites don’t exist. This would be a strong indication that these are `.onion` websites (only available to access if you are coming through a TOR node and not the regular internet). 

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-18 23:01:59 UTC`
- **Event:** The user "labus" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-18 23:04:14 UTC`
- **Event:** The user "labus" executed the file `tor-browser-windows-x86_64-portable-14.5.exe` in silent mode (Indicates an attempt to install without user interaction or GUI prompts), initiating a background installation of the TOR Browser. 
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-18 23:05:04 UTC`
- **Event:** The user opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **SHA256:** `3613fc46eab116864d28b7a3af1b7301fc0309bf3ba99c661a8c36ad5c848d02` (VirusTotal confirms this matches the official TOR Browser Portable EXE)

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-19 04:05:17 UTC`
- **Event:** A network connection to URL https://www.3ohv4urbp74k3hgmewtx3bnka.com was made with IP `46.38.254.168` over port `40000` by user was established using `tor.exe`, confirming TOR browser network activity. Attempting to open this URL in a regular browser results in an error, strongly suggesting it is a .onion or dark web site only reachable through the TOR network.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labus\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-19T04:05:21.1479442Z` - Connected to `46.4.74.237` on port `8080`.
  - `2025-04-19T04:05:21.2675715Z` - Connected to `65.109.71.88` on port `20257`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-19T04:18:47.1816015Z`
- **Event:** The user created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities. Placing it in a folder such as ProgramData further suggest that the user intended to keep it outside of everyone's attention.
- **Action:** File creation detected.
- **File Path:** `C:\ProgramData\tor-shopping-list.txt`

---

## Summary

The user `labus` on the `windows-workstation-1729` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on \ProgramData, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file. We don't have enough information to determine that there was any illegal activity as the traffic was encrypted. We would need to have the forensic team involved to determine if there are any artifacts of illegal activity left in the host.

---

## Response Taken

TOR usage was confirmed on the endpoint `windows-workstation-1729` by the user `labus`. The device was isolated, and the user's direct manager was notified, as well as a report provided to her.

---
