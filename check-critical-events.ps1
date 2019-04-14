
#### Security Log Logon Events ################################
# 4624 - An account was successfully logged on.
# 4634 - An account was successfully logged off.
# 4672 - Special Privileges assigned to new logon
################################
Get-winEvent -FilterHashtable @{LogName="Security"; ID=4624,4634,4672}


#### Security Log Critical Events ################################
# 4720 - A user account was created
# 4722 - (626) A user account was enabled
# 4724 - An attempt was made (not by the user) to reset an account's password and it failed to meet password policy
# 4738 - A user account was changed. Subject account did the changing to the Target account.
# 4732 - A member was added to a security enabled local group
# 1102 - The audit log was cleared
################################
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4720,4722,4724,4738,4732,1102}

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
#
################################
Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-AppLocker/EXE and DLL"; ID=8003}
Get-AppLockerFileInformation –EventLog –Logname "Microsoft-Windows-AppLocker\EXE and DLL" –EventType Allowed –Statistics
#### EMET Events ################################
# 
################################
