<#
    .Synopsis
        This script will input critical events from the json files produced by the Get-CriticalWinEvents.ps1 
		script and provide some statistics for analysis.
		
    .Description
		This script is written specifically to read in critical events from the JSON files produced after running
		Get-CriticalWinEvents.ps1.  The files should be located in the InputDirectory specified and should be 
		the only files in that directory.
		
    .Example
		./Analyze-CriticalWinEvents.ps1 -InputDirectory c:\Users\defender\Desktop\CriticalEvents\ -OutputDirectory
	
	.Parameter InputDirectory
        Specifies the path to the directory where the JSON files are stored. The default is the current directory.
		
	.Parameter CriticalEventsFile
		Specifies the path to the csv file that was used when retrieving the event logs with 
		Get-CriticalWinEvents.ps1. This file is required for the script to run. By default, it 
		looks for the file named CriticalEvents.csv located in the same directory. 
		
	.Parameter OutputDirectory
		Specifies the path to write the analysis files. The default is the current directory.
		
	.Notes
        NAME: ./Analyze-CriticalWinEvents.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.00
        LASTEDIT: 10 OCT 2020
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
	
Param(
	
	[string] $InputDirectory = ".",
	
	[string] $CriticalEventsFile = "CriticalEvents.csv",
	
	[string] $OutputDirectory = "."
	
)


#-------------------------------- Input Verification --------------------------------#
# Ensure output directory exists
if (-not (test-path $OutputDirectory)) {
	write-host "$OutputDirectory does not exist. Please run again with a valid output directory" -foregroundcolor Red
	exit
}

# ensure critical events file exists
if (-not (test-path $InputDirectory)) {
	write-host "$InputDirectory does not exist. Please run again with a valid input directory." -foregroundcolor Red
	exit
}

# ensure full paths are used even if relative is passed in
$InputDirectory = resolve-path $InputDirectory
$OutputDirectory = resolve-path $OutputDirectory

# Ensure output directory ends with \
if ($OutputDirectory[-1] -ne "\") {
	$OutputDirectory = $OutputDirectory + "\"
}

#-------------------------------- Variables --------------------------------#
$TimeRun = get-date -UFormat "%Y%m%dT%H%M"
$OutputFile = $OutputDirectory + 'CriticalWinEventsAnalysis_' + $TimeRun + ".txt"

$CriticalEvents = import-csv $CriticalEventsFile


#-------------------------------- Main --------------------------------#

# Read in all files to create one array of all event objects
write-host "[] Reading in files from $InputDirectory" -foregroundcolor cyan

$AllEventFiles = get-childitem $InputDirectory

$ListOfFileEventLists= foreach ($EventFile in $AllEventFiles){ get-content $EventFile.FullName | convertfrom-json}
$AllEvents = foreach ($FileEventList in $ListOfFileEventLists) { $FileEventList }

write-host "[] Calculating statistics" -foregroundcolor cyan

function Write-ToFile() {
	# Gather some basic statistics
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"======================== Critical Windows Events Analysis ==================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

	"`n`n============================================================================="
	"The following files were analyzed: "
	"============================================================================="
	"Directory: $OutputDirectory "
	get-childitem $InputDirectory | format-table Name,LastWriteTime,Length
	"-----------------------------------------------------------------------------"
	"Total number of files: $($AllEventFiles.count)"
	"Total number of events: $($AllEvents.count)"

	"`n============================================================================="
	"Number of Events Retrieved by Event ID:"
	"============================================================================="
	$AllEvents | Group-Object -Property id | format-table Count,@{Label="EventID"; Expression={$_.Name}}
	"`n============================================================================="
	"Number of Events Retrieved by Log Name:"
	"============================================================================="
	$AllEvents | Group-Object -Property LogName | format-table Count,@{Label="LogName"; Expression={$_.Name}}
	"`n============================================================================="
	"Number of Events Retrieved by Machine Name:"
	"============================================================================="
	$AllEvents | Group-Object -Property MachineName | format-table Count,@{Label="MachineName"; Expression={$_.Name}}
	"`n============================================================================="
	"Number of Events Retrieved by Event Message:"
	"============================================================================="
	$AllEvents | Group-Object -Property message | sort-object -Property count -Descending| format-table Count,@{Label="Message"; Expression={$_.Name}} -Autosize
}


write-host "[] Writing output to $OutputFile" -foregroundcolor cyan
Write-ToFile | write-output | out-file $OutputFile -encoding utf8




