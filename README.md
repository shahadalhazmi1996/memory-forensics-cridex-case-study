# Memory Forensics Case Study: Investigating a Cridex Banking-Trojan Infection

Analysis of a Windows XP memory image captured after a spearphishing incident, using the **Volatility Framework 2.6**.
The full write-up is in [`Memory_Forensics_Cridex_Case_Study.pdf`](Memory_Forensics_Cridex_Case_Study.pdf).

**Author:** Shahad Mansour Alhazmi

## Scenario

A manager opened an attachment from a spearphishing email and noticed nothing. Later, unusual activity appeared in the company accounts, and first responders captured a memory image of the machine. The goal was to find out what ran on the system, how it communicated, and what the attacker was after.

| Item | Details |
|---|---|
| Evidence | `project1-c.vmem` (536,870,912 bytes, training sample, not included in this repository) |
| Operating system | Windows XP SP3 x86 (`WinXPSP3x86`) |
| Acquisition time | 2012-07-22 02:45:08 UTC |
| Tools | Volatility 2.6, certutil, PowerShell, VirusTotal, ipinfo.io |

## Key findings

- **Injected code in two processes:** `explorer.exe` (PID 1484) and `reader_sl.exe` (PID 1640, Adobe Reader Speed Launcher). Both contain a PE image in private `PAGE_EXECUTE_READWRITE` memory, found with `malfind`.
- **`explorer.exe` is the only process talking to the internet**, with connections to `41.168.5.140:8080` (South Africa) and `125.19.103.198:8080` (India).
- **The payloads are identified as Cridex** by 60/72 and 61/72 antivirus engines on VirusTotal.
- **Banking-related strings** (Chase, TD Bank, Authorize.net) and a probable command-and-control URL (`http://188.40.0.138:8080/zb/v_01_a/in/cp.php`, Germany) were recovered from process memory.
- **No hidden processes:** `pslist`, `psscan` and `psxview` agree on the same 17 processes, and all command lines and paths are legitimate. The detection came from memory content and behavior.

## Method

1. `imageinfo` to identify the profile.
2. `pslist`, `psscan`, `pstree`, `psxview`, `cmdline` to enumerate processes and check for hidden ones.
3. `malfind`, `ldrmodules`, `dlllist` to look for injected or hidden code.
4. `connections`, `connscan`, `sockets`, `sockscan` to map network activity and socket creation times.
5. `procdump`, `malfind -D`, `certutil -hashfile` and VirusTotal to extract and check artifacts.
6. `memdump` and PowerShell regular expressions to extract URLs and IP addresses.

## Timeline (UTC)

| Time | Event |
|---|---|
| 02:42:31 | System boot (`smss.exe`) |
| 02:42:36 | `explorer.exe` and `reader_sl.exe` start |
| 02:43:01 | Last Windows service sockets created |
| **02:44:45** | **`explorer.exe` opens TCP 1038 to `41.168.5.140:8080`** |
| 02:45:08 | Memory image captured |

## Network indicators

| IP address | Location | Owner | Role |
|---|---|---|---|
| 41.168.5.140 | Johannesburg, South Africa | AS36937 Liquid Telecommunications | Active connection from `explorer.exe` (port 8080) |
| 125.19.103.198 | Kota, India | AS9498 Bharti Airtel | Closed connection from `explorer.exe` (port 8080) |
| 188.40.0.138 | Falkenstein, Germany | AS24940 Hetzner Online | Probable C2 address found in process memory |

Geolocation is approximate and may point to compromised third-party hosts.

## File hashes (SHA-256)

| Process | Artifact | SHA-256 | VirusTotal |
|---|---|---|---|
| explorer.exe | Injected region | `e00a1143fea8568f5bcbe2793c6b87032ba57f2fdd122266ea799658169d36b2` | 60/72 (Cridex) |
| explorer.exe | Process image | `48db195007e5ae9fc1246506564af154927e9f3fbfca0b4054552804027abbf2` | 34/70 (generic labels) |
| reader_sl.exe | Injected region | `cbe5f4afd18753839d7e47ee41e6a6c1a1d03e806a77ba7a585ac7b7cad92450` | 61/72 (Cridex) |
| reader_sl.exe | Process image | `5b136147911b041f0126ce82dfd24c4e2c79553b65d3240ecea2dcab4452dcb5` | 20/58 (generic labels) |

The process images received only generic labels and should not be called Cridex; the payload lives in the injected regions.

## Screenshots

| | |
|---|---|
| ![VirusTotal explorer injected](images/vt_explorer_injected_region.png) | ![VirusTotal reader_sl injected](images/vt_reader_sl_injected_region.png) |
| VirusTotal: region injected into `explorer.exe` | VirusTotal: region injected into `reader_sl.exe` |

More screenshots (VirusTotal for the process images and ipinfo.io lookups) are in the [`images`](images) folder.

## Limitations

- The findings come from one memory image.
- The memory image alone cannot prove which process was infected first. Adobe Reader is a plausible entry point for a malicious attachment, but `reader_sl.exe` started in the same second as `explorer.exe`, which suggests it is launched at logon.
- The link between `188.40.0.138` and the infection is an inference from the URL structure and port.
- VirusTotal results are stored analyses from earlier scans.
