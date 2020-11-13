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
		
	.Parameter StartTime
		Specifies the  StartTime to look for events created after a specific date.  
		Specify a string in the format:
			"2020-10-18 10:10:10.000Z"
		Default StartTime is 1 day before script run time calculated with:
			(get-date) - ((New-TimeSpan -Day 1)
			
	.Parameter EndTime
		Specifies the the End Time to look for events created before a specific date.
		Specify a string in the format:
			"2020-10-18 10:10:10.000Z"
		Default EndTime is script run time calculated with:
			(get-date)
		
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
			
	.Parameter EvtxFile
		Specifies the path to retrieve all critical events from a Windows Event file (.evtx).
		
	.Parameter OutputDir
		Specifies the directory to save output files.
		
    .Notes
        NAME: ./Get-CriticalWinEvents.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.10
        LASTEDIT: 8 OCT 2020
        CHANGELOG:
            1.00 - initial script 
			1.1  - additional functionality Evtx file
        Output Colors:
        Cyan - Informational
        Yellow - Warning
        Red - Error
		
	.Link
		https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm

#>
#Requires -RunAsAdministrator



## NEED TO ADD SYSMON EVENTS

#-------------------------------- Parameters --------------------------------#
[cmdletbinding(
        DefaultParameterSetName='byLogFile'
    )]
	
Param(

	[int64 ] $Max = 0,
	
	[string] $StartTime,
	
	[string] $EndTime,
	
	[array] $ComputerNames = (,"localhost"),
	
	[string] $CriticalEventsFile = "CriticalEvents.csv",
	
	[string] $OutputDir = ".",
	
	[Parameter(
		ParameterSetName='bycategory'
	)]
	[ValidateSet('All','AccountActivity','ApplicationCrashes','ApplicationWhitelisting','ClearingEventLogs','DriverManagement','ExternalMediaDetection','GroupPolicyErrors','KernelDriveSigning','MobileDeviceActivity','PrintingServices','SysmonSecurity','SoftwareAndServiceInstallation','SystemOrServiceFailures','WindowsDefenderActivity','WindowsFirewall','WindowsUpdateErrors')]
	[array] $Categories,
	
	[Parameter(
		ParameterSetName='byLogFile',
		Mandatory = $true
	)]
	[ValidateSet('All','Application','Setup','Sysmon','System','WindowsUpdateClient','PrintService','KernelPnPDeviceConfiguration','ProgramInventory','WindowsDefender','Security','WindowsFirewall','CodeIntegrity','WLANAutoConfig','AppLockerEXEandDLL','NetworkProfile')]
	[array] $LogFiles, 
	
	[Parameter(
		ParameterSetName='evtxFile'
	)]
	[string] $EvtxFile
	
)

#-------------------------------- Input Verification --------------------------------#
# ensure full paths are used even if relative is passed in
$OutputDir = resolve-path $OutputDir

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

# if an events file path is specified, make sure it is valid
if ($EvtxFile -and (-not (test-path $EvtxFile))) {
	write-host "$EvtxFile does not exist. Please run again with a valid path for the evtx file" -foregroundcolor Red
	exit
}

# set categories to all if 'All' was specified on the command line
if ($Categories -contains 'All') {
	$Categories = @('AccountActivity','ApplicationCrashes','ApplicationWhitelisting','ClearingEventLogs','DriverManagement','ExternalMediaDetection','GroupPolicyErrors','KernelDriveSigning','MobileDeviceActivity','PrintingServices','SoftwareAndServiceInstallation','SysmonSecurity','SystemOrServiceFailures','WindowsDefenderActivity','WindowsFirewall','WindowsUpdateErrors')
}

# set logfiles to all if 'All' was specified on the command line
if ($LogFiles -contains 'All') {
	$LogFiles = @('Application','Setup','Sysmon','System','WindowsUpdateClient','PrintService','KernelPnPDeviceConfiguration','ProgramInventory','WindowsDefender','Security','WindowsFirewall','CodeIntegrity','WLANAutoConfig','AppLockerEXEandDLL','NetworkProfile')
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

if ($StartTime -ne ""){
	$StartDateTime = (Get-Date $StartTime)
} else {
	$StartDateTime = (Get-date) - (New-TimeSpan -Day 1)
}

if ($EndTime -ne ""){
	$EndDateTime = (Get-Date $EndTime)
} else {
	$EndDateTime = Get-date
}	

if ($EvtxFile -ne ""){
	$EvtxBasename = get-childitem $EvtxFile | foreach-object {$_.Basename}
	$EvtxFile = resolve-path $EvtxFile
}

<#   Still need to incorporate or address if remote computers will be accessed
$cred = get-credential
$pass = $cred.getnetworkcredential().password
$user = $cred.username #>

#-------------------------------- Functions --------------------------------#
function Write-ToJsonFile{

	param (
		[string]$outfile,
		[string]$text
	)
	
	#write-host $outfile
	if ($text.length -gt 5) {
		# remove the final comma before closing the list
		if ($text[-1] -eq ',') {
			$text = $text.substring(0,$text.length-1) 
			$text +=  "]"
		}

		write-host "[] Writing critical events to $outfile." -foregroundcolor Green
		write-host ""
		# write complete json of all objects for all log files for a particular category
		$text | out-file $outfile -append -encoding utf8
	}
	 
}


#-------------------------------- Main --------------------------------#
# Retrieving Critical Events from specified log files

if ($PSCmdlet.ParameterSetName -eq 'byLogFile') {
	foreach ($LogFile in $LogFiles){
		$OutputFile = $OutputDir + $LogFile + '_' + $TimeRun +'_events.json'
		$LogName = ($CriticalEvents | where-object -property LogFileshort -eq $LogFile   | select-object -property LogFilefull -first 1).LogFilefull
		$id = $CriticalEvents | where-object -property LogFileshort -eq $LogFile  | select-object -property eventid -expandproperty eventid 
		$CritInfo = $CriticalEvents | where-object -property LogFileshort -eq $LogFile  | select-object -property eventid,description 
		#$id.length
		write-host ""
		write-host "[] Retrieving critical events in $LogFile log ($LogName) starting at $StartDateTime and ending at $EndDateTime." -foregroundcolor Cyan
		write-host "Looking for these Critical Events:" -foregroundcolor Cyan
		$CritInfo | ft eventid,description -wrap
		
		# create variable to hold string output to write to file and start it with "["
		$jsonOutput = "["
		
		foreach ($ComputerName in $ComputerNames) {
			write-host "[] Retrieving events from $ComputerName." -foregroundcolor Cyan
			try {
				$jsonEvents = Get-Winevent -ComputerName $ComputerName -filterhashtable @{LogName=$LogName; ID=$id; StartTime=$StartDateTime; EndTime = $EndDateTime;} @MaxEvents -ErrorAction stop | foreach-object { $_ | convertto-json  }
				# join each object's json with a comma as a list/array of json objects and add to output string
				$jsonOutput += [string]::join(",",$jsonEvents)
				# need a trailing , between json object lists for each logfile in a specific category.
				$jsonOutput += ','
				
			} catch {
				if ($_.Exception.Message -eq "No events were found that match the specified selection criteria." ) { 
					write-host "No Critical Events found in $LogFile ." -foregroundcolor Yellow			
				}
			}
		
		}
		Write-ToJsonFile -outfile $OutputFile -text $jsonOutput
		
	}
	
	
# Retrieving Critical Events from specified categories
} elseif ($PSCmdlet.ParameterSetName -eq 'bycategory') {
	foreach ($category in $Categories) {
		$OutputFile = $OutputDir + $category + '_' + $TimeRun  + '_events.json'
		$CatEvents = $CriticalEvents | where-object -property category -eq $category
		$CatLogFiles = $CatEvents | select-object -property LogFilefull -unique -expandproperty LogFilefull
		$CritInfo = $CatEvents | select-object -property eventid,description
		
		write-host ""
		write-host "[] Retrieving critical events in $category starting at $StartDateTime and ending at $EndDateTime." -foregroundcolor Cyan
		write-host "Looking for these Critical Events:" -foregroundcolor Cyan
		$CritInfo | ft eventid,description -wrap
		
		# create variable to hold string output to write to file and start it with "["
		$jsonOutput = "["
		
		foreach ($ComputerName in $ComputerNames) {
			write-host "[] Retrieving events from $ComputerName." -foregroundcolor Cyan
			foreach ($CatLogFile in $CatLogFiles) {
				$id = $CatEvents | where-object -property LogFilefull -eq $CatLogFile | select-object -property eventid -expandproperty eventid 
				#$id.length
				try {
					$jsonEvents = Get-Winevent -ComputerName $ComputerName -filterhashtable @{LogName=$CatLogFile; ID=$id; StartTime=$StartDateTime; EndTime = $EndDateTime;} @MaxEvents -ErrorAction stop | foreach-object {$_ | ConvertTo-Json } 
					
					# join each object's json with a comma as a list/array of json objects and add to output string
					$jsonOutput += [string]::join(",",$jsonEvents)
					# need a trailing , between json object lists for each logfile in a specific category.
					$jsonOutput += ','
					
				} catch {
					if ($_.Exception.Message -eq "No events were found that match the specified selection criteria." ) { 
						write-host "No Critical Events found in $CatLogFile for category $category ." -foregroundcolor Yellow
					}
				}
			
			}
		}

		Write-ToJsonFile -outfile $OutputFile -text $jsonOutput

	}	
} else {
	$OutputFile = $OutputDir + $EvtxBasename + '_' + $TimeRun + '_events.json'
	$FileEventsIds = $CriticalEvents | select-object -property eventid -expandproperty eventid | sort-object -Unique
	write-host ""
	write-host "[] Retrieving all critical events in $EvtxFile." -foregroundcolor Cyan

	# create variable to hold string output to write to file and start it with "["
	$jsonOutput = "["
	
	# filterhashtable seems to have a max of 23 items for the ID values so need to loop
	$start =0
	$end = 19
	
	while ($end -lt $FileEventsIds.length){
	
		try {
			#Get-Winevent -filterhashtable @{ Path=$EvtxFile; ID=$FileEventsIds[$start..$end]; } -ErrorAction stop | foreach-object {$_.toxml()}
			$jsonEvents = Get-Winevent -filterhashtable @{ Path=$EvtxFile; ID=$FileEventsIds[$start..$end]; } -ErrorAction stop | foreach-object {$_ | convertto-json}
			# join each object's json with a comma as a list/array of json objects and add to output string
			$jsonOutput += [string]::join(",",$jsonEvents)
			# need a trailing , between json object lists for each logfile in a specific category.
			$jsonOutput += ','

		} catch {
			if ($_.Exception.Message -eq "No events were found that match the specified selection criteria." ) { 
				write-host "No Critical Events with IDs $($FileEventsIds[$start..$end]) found in $EvtxFile.`n" -foregroundcolor Yellow
			}
		}
		
		$start = $start +20
		$end = $end +20

	}
	
	Write-ToJsonFile -outfile $OutputFile -text $jsonOutput
}

# Create Readme to describe importing into splunk
$OutputReadme = $OutputDir + "SplunkDataUpload_README.txt"
write-host "`nANALYSIS:`n`nTo properly import the json output files into Splunk, follow the instructions in $OutputReadme file. `n" -foregroundcolor Yellow
write-host "To get summary data and run a hasty analysis, run the Analyze-CriticalWinEvents.ps1 script on the json output files.`n`n`n" -foregroundcolor Yellow

"# How to Ingest json files created by Get-CriticalWinEvents.ps1 `n
1) In Splunk, click on 'Add Data' and then click 'Upload'
2) Click 'Select File' and browse to the output json file.
3) Click 'Next'.
4) The Source type should recognize the file as _json but there should be a warning in the table stating it failed to parse the timestamp.
5) Click the '>' next to Advanced and then click 'New Setting'.
6) Name it TIME_PREFIX and give it the value '\\/Date\(' (without the quotes). Click Apply Settings.
7) Scroll the frame back up and click 'Save As'. Name the Source Type 'CriticalWinEvents_json' and click 'Save'.
8) Click Next. Set the Input Settings for host and index based on where you retrieved the event logs and what index you want to use.
9) Click Review. Click Submit.
10) The data should now be available for searching." | out-file $OutputReadme

