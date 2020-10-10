<#
    .Synopsis
        This script will retrieve critical events from the windows event log and save them to a json file.
    .Description
		This script is configured to retrieve critical events from the Windows Event Log.
		The critical events are those identifed in the NSA Whitepaper "Spotting the Adversary 
		with Windows Event Log Monitoring". Alternatively, you supply a properly formatted 
		CSV file with Critical Events.  The script can retrieve all critical events from a 
		specified log file, or it can retrieve all critical events from a particular threat 
		category as specified in the whitepaper. The script will retrieve the logs from the 
		localhost by default but can also be given a list of hostnames to connect to for retrieval.
		The script will write the retrieved events to files by log file or category name in JSON 
		format for easy parsing or import into other tools.
		
    .Example
        ./Get-CriticalWinEvents.ps1 -ComputerName

    .Parameter ComputerNames
        [Optional] Comma separated list of computer hostnames to retrieve critical events from. 
		Type the NetBIOS name, an Internet Protocol (IP) address, or the fully qualified
        domain name of the computer. Default is "localhost".
		
	.Parameter Max
        [Optional] Maximum number of events to return. Default is all events.
		
	.Parameter CriticalEventsFile
		[Optional] Specifies the path to the csv file containing the critical events 
		(Event ID, Category, Description, LogFileFull, and LogFileshort)
		
	.Parameter Categories
        Specifies to retrieve all critical events from a particular category, regardless of log 
		file location.
		
	.Parameter LogFiles	
		Specifies to retrieve all critical events from a particular log file, regardless of category 
		of events. This is the default functionality if neither LogFiles or Categories are specified.
		
	.Parameter OutputDir
		Specifies the directory to save output files.
		
    .Notes
        NAME: ./Get-CriticalWinEvents.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.00
        LASTEDIT: 8 OCT 2020
        CHANGELOG:
            1.00 - initial script 
    
        Output Colors:
        White - Input Required
        Cyan - Informational
        Yellow - Warning
        Red - Error

#>
#-------------------------------- Parameters --------------------------------#
[cmdletbinding(
        DefaultParameterSetName='byLogFile'
    )]
	
Param(

	[int64 ] $Max = 0,
	
	[array] $ComputerNames = (,"localhost"),
	
	[string] $CriticalEventsFile = "CriticalEvents.csv",
	
	[string] $OutputDir = ".",
	
	[Parameter(
		ParameterSetName='bycategory'
	)]
	[ValidateSet('AccountActivity','ApplicationCrashes','ApplicationWhitelisting','ClearingEventLogs','DriverManagement','ExternalMediaDetection','GroupPolicyErrors','KernelDriveSigning','MobileDeviceActivity','PrintingServices','SoftwareAndServiceInstallation','SystemOrServiceFailures','WindowsDefenderActivity','WindowsFirewall','WindowsUpdateErrors')]
	[array] $Categories,
	
	[Parameter(
		ParameterSetName='byLogFile',
		Mandatory = $true
	)]
	[ValidateSet('Application','Setup','System','WindowsUpdateClient','PrintService','KernelPnPDeviceConfiguration','ProgramInventory','WindowsDefender','Security','WindowsFirewall','CodeIntegrity','WLANAutoConfig','AppLockerEXEandDLL','NetworkProfile')]
	[array] $LogFiles 
	
)


#-------------------------------- Variables --------------------------------#
if ($OutputDir[-1] -ne "\") {
	$OutputDir = $OutputDir + "\"
}

<# $cred = get-credential
$pass = $cred.getnetworkcredential().password
$user = $cred.username #>

<# $loglookup = @{'Application' = 'Application';
	'Setup' = 'Setup';
	'System' = 'System';
	'WindowsUpdateClient' = 'Microsoft-Windows-WindowsUpdateClient/Operational';
	'PrintService' = 'Microsoft-Windows-PrintService/Operational';
	'KernelPnPDeviceConfiguration' = 'Microsoft-Windows-Kernel-PnP/Device Configuration';
	'ProgramInventory' = 'Microsoft-Windows-Application-Experience/Program-Inventory';
	'WindowsDefender' = 'Microsoft-Windows-Windows Defender/Operational';
	'Security' = 'Security';
	'WindowsFirewall' = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';
	'CodeIntegrity' = 'Microsoft-Windows-CodeIntegrity/Operational';
	'WLANAutoConfig' = 'Microsoft-Windows-WLAN-AutoConfig/Operational';
	'AppLockerEXEandDLL' = 'Microsoft-Windows-AppLocker/EXE and DLL';
	'NetworkProfile' = 'Microsoft-Windows-NetworkProfile/Operational'
} #>

$CriticalEvents = import-csv $CriticalEventsFile

if ($PSCmdlet.ParameterSetName -eq 'byLogFile') {
	foreach ($LogFile in $LogFiles){
		$OutputFile = $OutputDir + $LogFile + '_events.json'
		$LogName = ($CriticalEvents | where-object -property LogFileshort -eq $LogFile   | select-object -property LogFilefull -first 1).LogFilefull
		$id = $CriticalEvents | where-object -property LogFileshort -eq $LogFile  | select-object -property eventid -expandproperty eventid 
		$CritInfo = $CriticalEvents | where-object -property LogFileshort -eq $LogFile  | select-object -property eventid,description 
		
		write-host ""
		write-host "[] Retrieving critical events in $LogFile log ($LogName)." -foregroundcolor Cyan
		write-host "Critical Events Reference:" -foregroundcolor Cyan
		$CritInfo | ft eventid,description -wrap

		foreach ($ComputerName in $ComputerNames) {
			write-host "Retrieving events from $ComputerName." -foregroundcolor Cyan
			if ($Max -eq 0) {
				get-winevent -ComputerName $ComputerName -filterhashtable @{LogName=$LogName; ID=$id;}  |  foreach-object {$_ | ConvertTo-Json} | out-file $OutputFile -append
			} else {
				get-winevent -ComputerName $ComputerName -filterhashtable @{LogName=$LogName; ID=$id;} -Max $Max  |  foreach-object {$_ | ConvertTo-Json} | out-file $OutputFile -append
			}
			
			write-host "[] Writing critical events to $OutputFile." -foregroundcolor Green
			write-host ""
		}
	}
	
	
	
} else {
	foreach ($category in $Categories) {
		$OutputFile = $category + '_events.json'
		$catevents = $CriticalEvents | where-object -property category -eq $category
		$catLogFiles = $catevents | select-object -property LogFilefull -unique -expandproperty LogFilefull
		$CritInfo = $catevents | select-object -property eventid,description
		
		write-host ""
		write-host "[] Retrieving critical events in $category." -foregroundcolor Cyan
		write-host "Critical Events Reference:" -foregroundcolor Cyan
		$CritInfo | ft eventid,description -wrap
		
		foreach ($ComputerName in $ComputerNames) {
			write-host "Retrieving events from $ComputerName." -foregroundcolor Cyan
			foreach ($catLogFile in $catLogFiles) {
				$id = $catevents | where-object -property LogFilefull -eq $catLogFile | select-object -property eventid -expandproperty eventid 
				if ($Max -eq 0) {
					get-winevent -ComputerName $ComputerName -filterhashtable @{LogName=$catLogFile; ID=$id;}  | foreach-object {$_ | ConvertTo-Json} | out-file $OutputFile -append
				} else {
					get-winevent -ComputerName $ComputerName -filterhashtable @{LogName=$catLogFile; ID=$id;} -Max $Max  | foreach-object {$_ | ConvertTo-Json} | out-file $OutputFile -append
				}
			}
		write-host "[] Writing critical events to $OutputFile." -foregroundcolor Green
		write-host ""
		}
	}	
}

