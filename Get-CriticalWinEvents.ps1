<#
    .Synopsis
        This script will retrieve critical events from the windows event log and save them to a json file.
    .Description
		This script is configured to retrieve critical events from the Windows Event Log.
		The critical events are those identifed in the NSA Whitepaper "Spotting the Adversary 
		with Windows Event Log Monitoring". Alternatively, you can supply a properly formatted 
		CSV file with Critical Events.  The script can retrieve all critical events from a 
		specified log file, or it can retrieve all critical events from a particular threat 
		category as specified in the whitepaper. The script will retrieve the logs from the 
		localhost by default but can also be given a list of hostnames to connect to for retrieval.
		The script will write the retrieved events to files by log file or category name in JSON 
		format for easy parsing or import into other tools.
		
    .Example
		.\Get-CriticalWinEvents.ps1 -Categories All -Max 2 -OutputDir .\testoutputfiles
		
		For each category, retrieves a maximum of 2 events per log file and writes the output
		in JSON format to a file in the testoutputfiles directory. Each file is named with 
		the category and time run. 
		Ex: .\testoutputfiles\AccountActivity_20201010T1305_events.json
		
	.Example
		.\Get-CriticalWinEvents.ps1 -Categories SoftwareAndServiceInstallation -OutputDir .\testoutputfiles\
		
		For the category SoftwareAndServiceInstallation, retrieves all events for each log file 
		that contains SoftwareAndServiceInstallation critical events as defined in the Critical Events 
		file. Writes the output in JSON format to a file in the testoutputfiles directory. The file
		is named with the category and time run. 
		Ex: .\testoutputfiles\SoftwareAndServiceInstallation_20201010T1328_events.json
		
	.Example
		.\Get-CriticalWinEvents.ps1 -LogFiles Security -OutputDir .\testoutputfiles\
		
		For the Security log, retrieves all events for any category as defined in the Critical
		Events file. Writes the output in JSON format to a file in the testoutputfiles directory. The file
		is named with the log file short name and time run.
		Ex: .\testoutputfiles\Security_20201010T1335_events.json
		
    .Parameter ComputerNames
        [Optional] Comma separated list of computer hostnames to retrieve critical events from. 
		Type the NetBIOS name, an Internet Protocol (IP) address, or the fully qualified
        domain name of the computer. Default is "localhost".
		
	.Parameter Max
        [Optional] Maximum number of events to return. Default is all events.
		
	.Parameter CriticalEventsFile
		Specifies the path to the csv file containing the critical events and their info.
		This file is required for the script to run. By default, it looks for the file named 
		CriticalEvents.csv located in the same directory. 
		
		If specifying a different file, it MUST be in the format: 
		EventID,Category,Description,LogFileFull,LogFileshort
		and use the Categories and shortened File names as listed in the Categories and LogFiles 
		Parameters.
		
	.Parameter Categories
        Specifies to retrieve all critical events from a particular category, regardless of log 
		file location.
		Possible Categories:
			All	
			AccountActivity	
			ApplicationCrashes
			ApplicationWhitelisting
			ClearingEventLogs
			DriverManagement
			ExternalMediaDetection
			GroupPolicyErrors
			KernelDriveSigning
			MobileDeviceActivity
			PrintingServices
			SoftwareAndServiceInstallation
			SystemOrServiceFailures
			WindowsDefenderActivity
			WindowsFirewall
			WindowsUpdateErrors
		
	.Parameter LogFiles	
		Specifies to retrieve all critical events from a particular log file, regardless of category 
		of events. This is the default functionality if neither LogFiles or Categories are specified. 
		The log file names have been shortened for ease of use.
		Possible Logfiles:
			All
			Application
			Setup
			System
			WindowsUpdateClient
			PrintService
			KernelPnPDeviceConfiguration
			ProgramInventory
			WindowsDefender
			Security
			WindowsFirewall
			CodeIntegrity
			WLANAutoConfig
			AppLockerEXEandDLL
			NetworkProfile
		
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
        Cyan - Informational
        Yellow - Warning
        Red - Error
		
	.Link
		https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm

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
	[ValidateSet('All','AccountActivity','ApplicationCrashes','ApplicationWhitelisting','ClearingEventLogs','DriverManagement','ExternalMediaDetection','GroupPolicyErrors','KernelDriveSigning','MobileDeviceActivity','PrintingServices','SoftwareAndServiceInstallation','SystemOrServiceFailures','WindowsDefenderActivity','WindowsFirewall','WindowsUpdateErrors')]
	[array] $Categories,
	
	[Parameter(
		ParameterSetName='byLogFile',
		Mandatory = $true
	)]
	[ValidateSet('All','Application','Setup','System','WindowsUpdateClient','PrintService','KernelPnPDeviceConfiguration','ProgramInventory','WindowsDefender','Security','WindowsFirewall','CodeIntegrity','WLANAutoConfig','AppLockerEXEandDLL','NetworkProfile')]
	[array] $LogFiles 
	
)

#-------------------------------- Input Verification --------------------------------#
# Ensure output directory ends with \
if ($OutputDir[-1] -ne "\") {
	$OutputDir = $OutputDir + "\"
}

# ensure output directory exists
if (-not (test-path $OutputDir)) {
	write-host "$OutputDir does not exist. Please run again with a valid output directory" -foregroundcolor Red
	exit
}

# ensure critical events file exists
if (-not (test-path $CriticalEventsFile)) {
	write-host "$CriticalEventsFile does not exist. Please run again with a valid Critical Events file." -foregroundcolor Red
	exit
}

# set categories to all if 'All' was specified on the command line
if ($Categories -contains 'All') {
	$Categories = @('AccountActivity','ApplicationCrashes','ApplicationWhitelisting','ClearingEventLogs','DriverManagement','ExternalMediaDetection','GroupPolicyErrors','KernelDriveSigning','MobileDeviceActivity','PrintingServices','SoftwareAndServiceInstallation','SystemOrServiceFailures','WindowsDefenderActivity','WindowsFirewall','WindowsUpdateErrors')
}

# set logfiles to all if 'All' was specified on the command line
if ($LogFiles -contains 'All') {
	$LogFiles = @('Application','Setup','System','WindowsUpdateClient','PrintService','KernelPnPDeviceConfiguration','ProgramInventory','WindowsDefender','Security','WindowsFirewall','CodeIntegrity','WLANAutoConfig','AppLockerEXEandDLL','NetworkProfile')
}

#-------------------------------- Variables --------------------------------#
$TimeRun = get-date -UFormat "%Y%m%dT%H%M"

$CriticalEvents = import-csv $CriticalEventsFile

# if a maximum number was specified, prepare the variable for "splatting" 
if ($Max -ne 0) { 
	$MaxEvents =  @{MaxEvents = $Max} 
} else { 
	$MaxEvents = ''
}

<# $cred = get-credential
$pass = $cred.getnetworkcredential().password
$user = $cred.username #>


#-------------------------------- Main --------------------------------#
# Retrieving Critical Events from specified log files

if ($PSCmdlet.ParameterSetName -eq 'byLogFile') {
	foreach ($LogFile in $LogFiles){
		$OutputFile = $OutputDir + $LogFile + '_' + $TimeRun +'_events.json'
		$LogName = ($CriticalEvents | where-object -property LogFileshort -eq $LogFile   | select-object -property LogFilefull -first 1).LogFilefull
		$id = $CriticalEvents | where-object -property LogFileshort -eq $LogFile  | select-object -property eventid -expandproperty eventid 
		$CritInfo = $CriticalEvents | where-object -property LogFileshort -eq $LogFile  | select-object -property eventid,description 
		
		write-host ""
		write-host "[] Retrieving critical events in $LogFile log ($LogName)." -foregroundcolor Cyan
		write-host "Looking for these Critical Events:" -foregroundcolor Cyan
		$CritInfo | ft eventid,description -wrap

		foreach ($ComputerName in $ComputerNames) {
			write-host "Retrieving events from $ComputerName." -foregroundcolor Cyan
			try {
				Get-Winevent -ComputerName $ComputerName -filterhashtable @{LogName=$LogName; ID=$id;} @MaxEvents -ErrorAction stop |  foreach-object {$_ | ConvertTo-Json} | out-file $OutputFile -append
			} catch {
				if ($_.Exception.Message -eq "No events were found that match the specified selection criteria." ) { 
					write-host "No Critical Events found in $LogFile ." -foregroundcolor Yellow			
				}
			}
			write-host "[] Writing critical events to $OutputFile." -foregroundcolor Green
			write-host ""
		}
	}
	
	
# Retrieving Critical Events from specified categories
} else {
	foreach ($category in $Categories) {
		$OutputFile = $OutputDir + $category + '_' + $TimeRun  + '_events.json'
		$CatEvents = $CriticalEvents | where-object -property category -eq $category
		$CatLogFiles = $CatEvents | select-object -property LogFilefull -unique -expandproperty LogFilefull
		$CritInfo = $CatEvents | select-object -property eventid,description
		
		write-host ""
		write-host "[] Retrieving critical events in $category." -foregroundcolor Cyan
		write-host "Looking for these Critical Events:" -foregroundcolor Cyan
		$CritInfo | ft eventid,description -wrap
		
		foreach ($ComputerName in $ComputerNames) {
			write-host "Retrieving events from $ComputerName." -foregroundcolor Cyan
			foreach ($CatLogFile in $CatLogFiles) {
				$id = $CatEvents | where-object -property LogFilefull -eq $CatLogFile | select-object -property eventid -expandproperty eventid 
				try {
					Get-Winevent -ComputerName $ComputerName -filterhashtable @{LogName=$CatLogFile; ID=$id;} @MaxEvents -ErrorAction stop | foreach-object {$_ | ConvertTo-Json} | out-file $OutputFile -append
				} catch {
					if ($_.Exception.Message -eq "No events were found that match the specified selection criteria." ) { 
						write-host "No Critical Events found in $CatLogFile for category $category ." -foregroundcolor Yellow
					}
				}
			
			}
		write-host "[] Writing critical events to $OutputFile." -foregroundcolor Green
		write-host ""
		}
	}	
}

