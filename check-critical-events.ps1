
#### Security Log Logon Events ################################
# 4624 - An account was successfully logged on.
# 4634 - An account was successfully logged off.
# 4672 - Special Privileges assigned to new logon
################################
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624,4634,4672}
get-winevent -filterhashtable @{LogName="Security"; ID=4624; StartTime = [datetime]::today } -max 1000 | foreach-object {([xml]$_.toxml()).Event.EventData.data[1].'#text'} | sort -unique
get-winevent -filterhashtable @{LogName="Security"; ID=4672; StartTime = [datetime]::today } -max 1000 | foreach-object {([xml]$_.toxml()).Event.EventData.data[1].'#text'} | sort -unique
get-winevent -filterhashtable @{Logname="Security"; ID=4624,4634,4672; StartTime = [datetime]::today}  |  foreach-object {$_ | ConvertTo-Json} | out-file "Security_4624_4634_4672.json"

$starttime = [datetime]::today  # 12:00 today
$starttime = [datetime]::now    # right now
$starttime = (get-date).addhours(-2)  # 2 hours ago

#### Security Log Critical Events ################################
# 4720 - A user account was created
# 4722 - (626) A user account was enabled
# 4724 - An attempt was made (not by the user) to reset an account's password and it failed to meet password policy
# 4738 - A user account was changed. Subject account did the changing to the Target account.
# 4732 - A member was added to a security enabled local group
# 1102 - The audit log was cleared
################################
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4720,4722,4724,4738,4732,1102} | sort-object -property ID | ft -wrap

#### System Log Critical Events ################################
# 7030 - Service marked as an interactive service but system configured to not allow interactive services. 
# 7045 - New Service Creation
# 1056 - DHCP Service detected on DC with no credentials configured for use with Dynamic DNS registrations.
# 10000 - RPCSS Create Process Failure - Unable to start a DCOM server.
# 10001 - RPCSS RunAs Create Process Failure - Unable to start a DCOM server.
# 10010 - Remote Event unsupported restart - Application or server restart failed after installation or update.
# 20001 - Driver Mgmt device installation - success or error code for failure
# 20002 - device attemped to connect but could not be authenticated and was rejected.
# 20003 - Driver Mmgt device instance service installation
# 24576 - Drivers successfully installed for device.
# 24577 - Bitlocker volume conversion (encryption started)
# 24579 - Bitlocker volume converstion (encryption completed)
################################
Get-WinEvent -FilterHashtable @{LogName="System"; ID=7030,7045,1056,10000,10001,10010,20001,20002,20003,24576,24577,24579}



#### System Log Critical Events ################################
# 2003 - Windows Firewall Configuration setting changed.
################################
Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; ID=2003}



#### AppLocker Events ################################
# 8003 - Applied only when the Audit only enforcement mode is enabled. Specifies that the .exe or .dll file would be blocked if the Enforce rules enforcement mode were enabled.
# 8004 - Access to <file name> is restricted by the administrator. Applied only when the Enforce rules enforcement mode is set. The .exe or .dll file cannot run.
# 8006 - Applied only when the Audit only enforcement mode is enabled. Specifies that the script or .msi file would be blocked if the Enforce rules enforcement mode were enabled.
# 8007 - Access to <file name> is restricted by the administrator. Applied only when the Enforce rules enforcement mode is set. The script or .msi file cannot run.
# 8021 - Packaged app audited.
# 8022 - Packaged app disabled.
# 8024 - Packaged app installation audited.
# 8025 - Packaged app installation disabled.
################################
Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-AppLocker/EXE and DLL"; ID=8003,8004,8006,8007,8021,8022,8024,8025}


################################
# outputs the file information for all the Audited events in the local event log. Audited events correspond to the Warning event in the AppLocker audit log.
################################
Get-AppLockerFileInformation -EventLog -EventType Audited
Get-AppLockerFileInformation -EventLog -EventType Denied
Get-AppLockerFileInformation -EventLog -EventType Allowed

#### Microsoft Defender Detection Events ################################
# 1006 - The antimalware engine found malware or other potentially unwanted software.
# 1007 - The antimalware platform performed an action to protect your system from malware or other potentially unwanted software.
# 1008 - The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed.
# 1009 - The antimalware platform restored an item from quarantine.
# 1010 - The antimalware platform could not restore an item from quarantine.
# 1015 - The antimalware platform detected suspicious behavior.
# 1116 - The antimalware platform detected malware or other potentially unwanted software.
# 1117 - The antimalware platform performed an action to protect your system from malware or other potentially unwanted software.
# 1118 - The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed.
# 1119 - The antimalware platform encountered a critical error when trying to take action on malware or other potentially unwanted software. 
################################
 Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational";id=1006,1007,1008,1009,1010,1015,1116,1117,1118,1119}


#### Microsoft Defender Error Events ################################
# 3002 - Real-time protection encountered an error and failed.
# 5001 - Real-time protection is disabled.
# 5004 - The real-time protection configuration changed.
# 5007 - The antimalware platform configuration changed.
# 5008 - The antimalware engine encountered an error and failed.
# 5010 - Scanning for malware and other potentially unwanted software is disabled.
# 5012 - Scanning for viruses is disabled.
################################
Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational";id=3002,5001,5004,5007,5008,5010,5012}


