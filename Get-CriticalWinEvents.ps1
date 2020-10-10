<#
    .Synopsis
        This script will retrieve critical events from the windows event log and save them to a json file.
    .Description
		This script is configured with critical events identifed by the NSA Whitepaper "Spotting the Adversary with Windows Event Log Monitoring"
		It will retrieve 
    .Example
        ./Get-CriticalWinEvents.ps1 -computername

    .Parameter computernames
        Computer hostname to connect to. Default is "localhost"
	.Parameter max
        Maximum number of events to return. Default is 1000. Use Zero (0) for all events.
	.Parameter criticalevents_file
		Specifies the csv file containing the critical events (Event ID, Category, Description, LogfileFull, and LogfileShort)
	.Parameter categories
        Specifies to retrieve all critical events from a particular category, regardless of log file location.
	.Parameter logfiles	
		Specifies to retrieve all critical events from a particular log file, regardless of category of events. This is the default functionality.
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
        DefaultParameterSetName='bylogfile'
    )]
	
Param(

	[int] $max = 1000,
	
	[array] $computernames = (,"localhost"),
	
	[string] $criticalevents_file = "CriticalEvents.csv",
	
	[Parameter(
		ParameterSetName='bycategory'
	)]
	[ValidateSet('AccountActivity','ApplicationCrashes','ApplicationWhitelisting','ClearingEventLogs','DriverManagement','ExternalMediaDetection','GroupPolicyErrors','KernelDriveSigning','MobileDeviceActivity','PrintingServices','SoftwareAndServiceInstallation','SystemOrServiceFailures','WindowsDefenderActivity','WindowsFirewall','WindowsUpdateErrors')]
	[array] $categories,
	
	[Parameter(
		ParameterSetName='bylogfile',
		Mandatory = $true
	)]
	[ValidateSet('Application','Setup','System','WindowsUpdateClient','PrintService','KernelPnPDeviceConfiguration','ProgramInventory','WindowsDefender','Security','WindowsFirewall','CodeIntegrity','WLANAutoConfig','AppLockerEXEandDLL','NetworkProfile')]
	[array] $logfiles 
	
)


#-------------------------------- Variables --------------------------------#


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

$criticalevents = import-csv $criticalevents_file

if ($PSCmdlet.ParameterSetName -eq 'bylogfile') {
	foreach ($logfile in $logfiles){
		$outputfile = $logfile + '_events.json'
		$logname = ($criticalevents | where-object {$_.logfileshort -eq $logfile }  | select-object -property logfilefull -first 1).logfilefull
		$id = $criticalevents | where-object {$_.logfileshort -eq $logfile }  | select-object -property eventid -expandproperty eventid 
		$critinfo = $criticalevents | where-object {$_.logfileshort -eq $logfile } | select-object -property eventid,description 
		
		write-host ""
		write-host "[] Retrieving critical events in $logfile log ($logname)." -foregroundcolor Cyan
		write-host "Critical Events Reference:" -foregroundcolor Cyan
		$critinfo | ft eventid,description -wrap

		foreach ($computername in $computernames) {
			write-host "Retrieving events from $computername." -foregroundcolor Cyan
			get-winevent -computername $computername -filterhashtable @{Logname=$logname; ID=$id;} -max $max  |  foreach-object {$_ | ConvertTo-Json} | out-file $outputfile -append
			
			write-host "[] Writing critical events to $outputfile." -foregroundcolor Green
			write-host ""
		}
	}
	
	
	
} else {
	foreach ($category in $categories) {
		$outputfile = $category + '_events.json'
		$catevents = $criticalevents | where-object {$_.category -eq $category}
		$catlogfiles = $catevents | select-object -property logfilefull -unique -expandproperty logfilefull
		$critinfo = $catevents | select-object -property eventid,description
		write-host $catlogfiles
		
		write-host ""
		write-host "[] Retrieving critical events in $category." -foregroundcolor Cyan
		write-host "Critical Events Reference:" -foregroundcolor Cyan
		$critinfo | ft eventid,description -wrap
		
		foreach ($computername in $computernames) {
			write-host "Retrieving events from $computername." -foregroundcolor Cyan
			foreach ($catlogfile in $catlogfiles) {
				$id = $catevents | where-object ($_.logfilefull -eq $catlogfile) | select-object -property eventid -expandproperty eventid
				get-winevent -computername $computername -filterhashtable @{Logname=$catlogfile; ID=$id;} -max $max | foreach-object {$_ | ConvertTo-Json} | out-file $outputfile -append
			}
		write-host "[] Writing critical events to $outputfile." -foregroundcolor Green
		write-host ""
		}
	}	
}

