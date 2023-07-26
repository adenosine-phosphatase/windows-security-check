# windows-security-check
This is a short python script that checks some basic security parameters.
I used a combination of checking the windows registry key, wmic and sc and some hashing functions to calculate the checksum of some critical DLLs for ZSCaler. 

There is another separate text file that contains hash of those DLLs calculated in the healthy state (and are used to compared against every new hash calculation to indicate potential file integrity changes - due to either legitimate software update or malicious injections).

1. wmic and sc are used to provide service status
2. checking windows registry required to check ZSCaler tunnel status

3. "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe" Windows Advanced Threat Protection servuice (servicename:"sense")
4. sc queryex sense
5. C:\Program Files\Windows Defender>MpCmdRun.exe 
6. WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct  Get displayName,timestamp /Format:List -> this runs with lowpriv access

Idea 1: calculate hash for some ZScaler and Defender DLLs, store them into the text file
Idea 1: continue to re-hash the same files to detect changes due to updates etc.

Idea 2: Check for processes being debugged and WDigest. 
Idea 2: Rewrite powershell into python https://www.cyberdrain.com/monitoring-with-powershell-monitoring-security-state/4

Idea 3: Check registry keys against new process for malware persistence
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run -> check key values
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce -> check key values

Also if the new keys are created for services under
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\services -> check only if key exists
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\services -> check only if key exists

Below is a typical output when no suspicious indicators have been detected.

![image](https://github.com/adenosine-phosphatase/windows-security-check/assets/17417863/89976293-acea-4a97-b5c0-25741e2357c4)
