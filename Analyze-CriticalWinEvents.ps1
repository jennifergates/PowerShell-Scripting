<#
    .Synopsis
        This script will input critical events from the json files produced by the Get-CriticalWinEvents.ps1 
		script and provide some statistics for analysis.
		
    .Description
		This script is written specifically to read in critical events from the JSON files produced after running
		Get-CriticalWinEvents.ps1.  The files should be located in the InputDirectory specified and should be 
		the only files in that directory.
		
		The script will produce a number of analysis files for further review or easy searching.
			- CriticalWinEventsAnalysis_<date>.txt - Summary info and short tables of goodness.
			- SuspiciousWordMatches_<data>.txt - Full event json for any event message field that matches a word.
			- SysmonProcessCreateCmdLines_<date>.txt - All Command Lines recorded by Sysmon events.
			- SysmonRecordedFileHashes_<date>.txt - All File hashes recorded by Sysmon events.
		
    .Example
		./Analyze-CriticalWinEvents.ps1 -InputDirectory c:\Users\defender\Desktop\CriticalEvents\ -OutputDirectory
	
	.Parameter InputDirectory
        Specifies the path to the directory where the JSON files are stored. The default is the current directory.
		
	.Parameter CriticalEventsFile
		Specifies the path to the csv file that was used when retrieving the event logs with 
		Get-CriticalWinEvents.ps1. This file is required for the script to run. By default, it 
		looks for the file named CriticalEvents.csv located in the same directory. 
		
	.Parameter SuspiciousWordsFile
		Optional. Specifies a txt file that contains suspicious words, one per line, to search for in the event message field.
		
	.Parameter SuspiciousRegexFile
		Optional. Specifies a txt file that contains suspicious regular expressions, one per line, to search for in the sysmon detected commandlines.
		
	.Parameter CmdLineWhitelistFile
		Optional. Specifies a text file that contains whitelisted command lines. Full or partial, one per line.
		Ex. C:\Users\D-o\AppData\Local\Microsoft\Teams\current\Teams.exe
		
	.Parameter OutputDirectory
		Specifies the path to write the analysis files. The default is the current directory.
		
	.Notes
        NAME: ./Analyze-CriticalWinEvents.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.10
        LASTEDIT: 1 NOV 2020
        CHANGELOG:
            1.00 - initial script 
			1.1  - new methodology and analysis
    
        Output Colors:
        Cyan - Informational
        Yellow - Warning
        Red - Error
		
	.Link
		https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm
		https://www.sans.org/webcasts/atmic-talk-self-compiling-malware-114085
		https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/

#>

#-------------------------------- Parameters --------------------------------#
	
Param(
	
	[string] $InputDirectory = ".",
	
	[string] $CriticalEventsFile = "CriticalEvents.csv",
	
	[string] $SuspiciousWordsFile,
	
	[string] $SuspiciousRegexFile,
	
	[string] $CmdLineWhitelistFile,
	
	[string] $OutputDirectory = "."
	
)


#-------------------------------- Input Verification --------------------------------#

$timestart = get-date
# Ensure output directory exists
if (-not (test-path $OutputDirectory)) {
	write-host "$OutputDirectory does not exist. Please run again with a valid output directory" -foregroundcolor Red
	exit
}

# ensure input directory exists
if (-not (test-path $InputDirectory)) {
	write-host "$InputDirectory does not exist. Please run again with a valid input directory." -foregroundcolor Red
	exit
}

# ensure suspicious words file exists, if provided
if ($SuspiciousWordsFile -and (-not (test-path $SuspiciousWordsFile))) {
	write-host "$SuspiciousWordsFile does not exist. Please run again with a valid suspicious word file." -foregroundcolor Red
	exit
}

# ensure suspicious regex file exists, if provided
if ($SuspiciousRegexFile -and (-not (test-path $SuspiciousRegexFile))) {
	write-host "$SuspiciousRegexFile does not exist. Please run again with a valid suspicious regex file." -foregroundcolor Red
	exit
}

#ensure process white lsit file exists, if provided	
if ($CmdLineWhitelistFile -and (-not (test-path $CmdLineWhitelistFile))) {
	write-host "$CmdLineWhitelistFile does not exist. Please run again with a valid Command Line Whitelist file." -foregroundcolor Red
	exit
}

# ensure critical events csv file exists
if (-not (test-path $CriticalEventsFile)) {
	write-host "$CriticalEventsFile does not exist. Please run again with a valid critical events csv file." -foregroundcolor Red
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
$SummaryAnalysisOutputFile = $OutputDirectory + 'SummaryAnalysis_' + $TimeRun + ".txt"
$LogonAnalysisOutputFile = $OutputDirectory + 'LogonAnalysis_' + $TimeRun + ".txt"
$SysmonAnalysisOutputFile = $OutputDirectory + 'SysmonAnalysis_' + $TimeRun + ".txt"
$SuspiciousWordMatchOutputFile = $OutputDirectory + 'SuspiciousWordMatches_' + $TimeRun + ".txt"
$FileHashesOutputFile = $OutputDirectory + 'SysmonRecordedFileHashes_' + $TimeRun + ".txt"
$CmdlineOutputFile = $OutputDirectory + 'SysmonProcessCreateCmdLines_' + $TimeRun + ".txt"
$AdditionalAnalysisOutputFile = $OutputDirectory + 'AdditionalAnalysis_' + $TimeRun + ".txt"
$CmdlineAnalysisOutputFile = $OutputDirectory + 'SysmonProcessCreateCmdLineAnalysis_' + $TimeRun + ".txt"

$CriticalEvents = import-csv $CriticalEventsFile



#------------------------- REGEX Definitions ------------------------------#

[regex]$SuspiciousRegNames = "Run|Shell|Scripts|UserInit|UserAssist"


#------------------------- functions --------------------------------------#

function Get-RegexFromWords {
	param (
		$File,
		$Separator
	)
	$s = ""
	foreach ($line in (Get-content $File)) {
			
		$s = $s + $line.replace('\','\\').replace('/', '\/').replace('.', '\.').replace('(','\(').replace(')', '\)') + $Separator
	}
	$s  = $s -replace '.$'
	[regex]$s
}

function Get-NormalizedName {
	# It seems the format of the message field can change by Windows version. Trying to Normalize Names. 
	param (
		$SplitName
	)
	
	$OldToNew = @{
		Subject_Logon_Type = 'Logon_Information_Logon_Type' 
		Logon_Type = 'Logon_Information_Logon_Type'
	}
	
	if ($OldToNew.keys -contains $SplitName){
		$RetName = $OldToNew[$SplitName]
	} else {
		$RetName = $SplitName
	}
	$RetName

}

function Get-LogonTypeDesc{
	param (
		$TypeCode
	)
	
	$CodeToDesc = @{
		'2' = '2 Interactive'
		'3' = '3 Network'
		'4' = '4 Batch'
		'5' = '5 Service'
		'7' = '7 Unlock'
		'8' = '8 NetworkCleartext'
		'9' = '9 NewCredentials'
		'10' = '10 RemoteInteractive'
		'11' = '11 CachedInteractive'
	}
	
	if ($CodeToDesc.keys -contains $TypeCode){
		$RetDesc = $CodeToDesc[$TypeCode]
	} else {
		$RetDesc = $TypeCode
	}
	$RetDesc
	
}

function Check-ParentChild{
	[CmdletBinding()]
	param (
		[parameter(ValueFromPipeline =  $true)]
		$Event1Obj
	)
	Begin {
		$parents= "winword.exe","excel.exe","powerpoint.exe","mspub.exe","outlook.exe","visio.exe","powershell.exe","teams.exe","iexplore.exe","chrome.exe","firefox.exe"
		$children= "jsc.exe","csc.exe","cmd.exe","msbuild.exe","powershell.exe"
	}
	Process {
		if ( ($parents | foreach-object {$Event1Obj.Message_ParentCommandLine.tolower().contains($_)}) -contains $true    -and    ($children | foreach-object {$Event1Obj.Message_CommandLine.tolower().contains($_)}) -contains $true ) {
			$Event1Obj
		}
	}

}
#------------------------ Create Objects from Events with Message field details -----------------------------#

# Read in all files to create one array of all event objects
write-host "[] Reading in files from $InputDirectory . " -foregroundcolor cyan
write-host "`tDepending on the number and size of files, this could take a few minutes." -foregroundcolor yellow

$AllEventFiles = get-childitem $InputDirectory | where -property name -like '*.json'

$ListOfFileEventLists= foreach ($EventFile in $AllEventFiles){ get-content $EventFile.FullName | convertfrom-json}
$AllEvents = foreach ($FileEventList in $ListOfFileEventLists) { $FileEventList }


# Parse event message by colon ":" and add items as additional noteproperties to the original event 
$AllSecurityEvents = $AllEvents | where-object -property logname -eq "Security" | foreach-object {
	$NewSecEvent = $_
	$header = ""
	foreach ($var in ($_.Message -split "`r`n")) {
		if ($var -like "*:*") {
			$name = ((($var -split ":", 2)[0]).trim()).replace(" ","_")
			$value = ((($var -split ":", 2)[1]).trim()).replace(" ","_")
			$name = $name -replace "[\(\)]", "_"
			
			# Needed to add line above info to avoid value name collisions
			if ($value.trim(" `r`n") -eq "") {
				$header = $name.trim("`r`n")
			} else {
				$name = $header+ "_"+$name
				$name = Get-NormalizedName($name)
				$NewSecEvent | Add-Member -MemberType NoteProperty -Name $name -Value $value
			}
		}
	}
	$NewSecEvent
}


#### SYSMON EVENTS
# Create collection of new objects for each event putting Sysmon message fields as their own properties in the object
$AllSysmonEvents = $AllEvents | where-object -property logname -eq "Microsoft-Windows-Sysmon/Operational" | foreach-object { 
	$NewEvent = $_
	foreach ($var in ($_.Message -split "`r`n" )) {
		$NewEvent |  Add-Member -MemberType NoteProperty -Name (('Message_'+$var -split ": ", 2)[0])  -Value ($var -split ": ", 2)[1]
	}
	$NewEvent
}

####################+++++++++++++++++++TESTING AREA ++++++++++++++++++++++++##############
#$AllEvents | where-object {($_.id -eq 104 -and $_.logname -eq "System") -or ($_.id -eq 1102 -and $_.logname -eq "Security")} | format-list Subject_Account_Name,Subject_Domain_Name,Subject_Logon_ID,TimeCreated,LogName,Id,UserID,Properties


#$AllSysmonEvents | where-object -property id -eq 1 | gm

####################+++++++++++++++++++TESTING AREA ++++++++++++++++++++++++##############

#------------------------ Use Objects to parse specifics from events -----------------------------#
write-host "[] Calculating statistics" -foregroundcolor cyan

function Get-SummaryAnalysis {
	# Gather some basic statistics
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"======================== Critical Windows Events Summary Analysis ==================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`nScript Run Time: $TimeRun"

	"`n`n=========================================================================================="
	"The following files were analyzed: "
	"=========================================================================================="
	"Directory: $OutputDirectory "
	$AllEventFiles| format-table Name,LastWriteTime,Length
	"-----------------------------------------------------------------------------"
	"Total number of files: $($AllEventFiles.count)"
	"Total number of events: $($AllEvents.count)"

	"`n=========================================================================================="
	"Number of Events Retrieved by Event ID:"
	"=========================================================================================="
	$AllEvents | Group-Object -Property id,LogName | format-table @{Label="Logname"; Expression={($_.Name -split ",")[1]}},@{Label="EventID"; Expression={($_.Name -split ",")[0]}},Count
	"`n=========================================================================================="
	"Number of Events Retrieved by Log Name:"
	"=========================================================================================="
	$AllEvents | Group-Object -Property LogName | format-table @{Label="LogName"; Expression={$_.Name}},Count
	"`n=========================================================================================="
	"Number of Events Retrieved by Machine Name:"
	"=========================================================================================="
	$AllEvents | Group-Object -Property MachineName | format-table @{Label="MachineName"; Expression={$_.Name}},Count
}

function Get-AdditionalAnalysis{
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"======================== Critical Windows Events Analysis ==================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`nScript Run Time: $TimeRun"
	"`n`n"
	"`n=========================================================================================="
	"Security Event ID 1102 or System Event ID 104 (logs cleared)"
	"=========================================================================================="
	$AllEvents | where-object {($_.id -eq 104 -and $_.logname -eq "System") -or ($_.id -eq 1102 -and $_.logname -eq "Security")} | format-list @{Label="------"; Expression={" "}},TimeCreated,LogName,ID,Subject_Account_Name,Subject_Domain_Name,Subject_Logon_ID,UserID,Properties
	
}

function Get-LogonAnalysis{
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"======================== Critical Windows Events Logon Events Analysis ==================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`nScript Run Time: $TimeRun"
	"`n`n"
	"`n=========================================================================================="
	"Number of Event ID 4624 Events by Logon Type, New Logon Account Name, and Network "
	"Info Source Address:"
	"=========================================================================================="
	$AllSecurityEvents | where-object -property id -eq 4624 | group-object -property Logon_Information_Logon_Type,New_Logon_Account_Name,Network_Information_Workstation_Name,Network_Information_Source_Network_Address | sort-object -property count -Descending | format-table Count,@{Label="Logon_Type"; Expression={Get-LogonTypeDesc(($_.Name -split ",")[0])}},@{Label="New_Logon_Account_Name"; Expression={($_.Name -split ",")[1]}},@{Label="Workstation_Name"; Expression={($_.Name -split ",")[2]}},@{Label="Source_Network_Address"; Expression={($_.Name -split ",")[3]}} -wrap

	"`n=========================================================================================="
	"Number of Event ID 4624, Logon Type 3 Events by Auth Package, New Logon Account 
	Name, and New Logon Account Domain (Possible Successful Pass-The-Hash Indicator):"
	"=========================================================================================="
	$AllSecurityEvents | where-object { $_.id -eq 4624 -and $_.Logon_Information_Logon_Type -eq 3 -and $_.Detailed_Authentication_Information_Authentication_Package -eq "NTLM" -and $_.New_Logon_Account_Name -ne "ANONYMOUS_LOGON" -and $_.New_Logon_Account_Domain -ne ((get-wmiobject Win32_ComputerSystem).Domain) } | group-object -property Detailed_Authentication_Information_Authentication_Package,New_Logon_Account_Name,New_Logon_Account_Domain | sort-object -Property count -Descending| format-table Count,@{Label="Authentication_Package"; Expression={($_.Name -split ",")[0]}},@{Label="New_Logon_Account_Name"; Expression={($_.Name -split ",")[1]}},@{Label="New_Logon_Account_Domain"; Expression={($_.Name -split ",")[2]}} -wrap

	"`n=========================================================================================="
	"Number of Event ID 4625, Logon Type 3 Events by Auth Package, New Logon Account 
	Name, and New Logon Account Domain (Possible Failed Pass-The-Hash Indicator):"
	"=========================================================================================="
	$AllSecurityEvents | where-object { $_.id -eq 4625 -and $_.Logon_Information_Logon_Type -eq 3 } | group-object -property Detailed_Authentication_Information_Authentication_Package,Account_For_Which_Logon_Failed_Account_Name,Account_For_Which_Logon_Failed_Account_Domain | sort-object -Property count -Descending| format-table Count,@{Label="Authentication_Package"; Expression={($_.Name -split ",")[0]}},@{Label="Failed_Account_Name"; Expression={($_.Name -split ",")[1]}},@{Label="Failed_Account_Domain"; Expression={($_.Name -split ",")[2]}}  -wrap
	
	"`n=========================================================================================="
	"Number of Event ID 4625 Events by Logon Type, Logon Failed Account Name, Network " 
	"Info Workstation Name, and Network Info Source Address:"
	"=========================================================================================="
	$AllSecurityEvents | where-object -property id -eq 4625 | group-object -property Logon_Information_Logon_Type,Account_For_Which_Logon_Failed_Account_Name,Failure_Information_Failure_Reason,Network_Information_Workstation_Name,Network_Information_Source_Network_Address | sort-object -property count -Descending | format-table Count,@{Label="Logon_Type"; Expression={Get-LogonTypeDesc(($_.Name -split ",")[0])}},@{Label="Failed_Account_Name"; Expression={($_.Name -split ",")[1]}},@{Label="Failure_Information_Failure_Reason"; Expression={($_.Name -split ",")[2]}},@{Label="Workstation_Name"; Expression={($_.Name -split ",")[3]}},@{Label="Source_Network_Address"; Expression={($_.Name -split ",")[4]}} -wrap
	
	"`n=========================================================================================="
	"Number of Event ID 4624 Logon Type 10 Logon Events by Account Name, and Logon ID, "
	"and Network Info Source Address (Remote Desktop Logon):"
	"=========================================================================================="
	$AllSecurityEvents | where-object { $_.id -eq 4624 -and $_.Logon_Information_Logon_Type -eq 10 } | group-object -property New_Logon_Account_Name, New_Logon_Logon_ID,Network_Information_Source_Network_Address | sort-object -property count -Descending | format-table Count,@{Label="New_Logon_Account_Name"; Expression={($_.Name -split ",")[0]}},@{Label="New_Logon_Logon_ID"; Expression={($_.Name -split ",")[1]}},@{Label="Source_Network_Address"; Expression={($_.Name -split ",")[2]}} -wrap
	
	"`n=========================================================================================="
	"Number of Event ID 4634 Logon Type 10 Logoff Events by Account Name, and Logon ID:"
	"=========================================================================================="	
	$AllSecurityEvents | where-object {$_.id -eq 4634 -and $_.Logon_Information_Logon_Type -eq 10 } | group-object -property Subject_Account_Name, Subject_Logon_ID | sort-object -property count -Descending | format-table Count,@{Label="New_Logon_Account_Name"; Expression={($_.Name -split ",")[0]}},@{Label="New_Logon_Logon_ID"; Expression={($_.Name -split ",")[1]}} -wrap
}

function Get-SysmonAnalysis{
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"======================== Critical Windows Events Sysmon Analysis ==================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`nScript Run Time: $TimeRun"
	"`n=========================================================================================="
	"Number of Event ID 10 (Process Access) Sysmon Events by Target Image"
	"=========================================================================================="
	$AllSysmonEvents | where-object -property id -eq 10  | group-object -property Message_TargetImage | sort-object -Property @{Expression = {$_.count}; Ascending = $false},name  |format-table count,@{Label="Message_TargetImage"; Expression={$_.Name}} -wrap

	"`n=========================================================================================="
	"Number of Event ID 1 (Process Create) Sysmon Events by Image"
	"=========================================================================================="
	$AllSysmonEvents | where-object -property id -eq 1  | group-object -property Message_Image | sort-object -Property @{Expression = {$_.count}; Ascending = $false},name  |format-table count,@{Label="Message_Image"; Expression={$_.Name}} -wrap
	
	"`n=========================================================================================="
	"Number of Event ID 1 (Process Create) Sysmon Events where Image name doesn't equal "
	"Original File name"
	"=========================================================================================="	
	$AllSysmonEvents | where-object -property id -eq 1 | where-object { ($_.Message_Image -split("\\"))[-1] -ne $_.Message_OriginalFileName -and $_.Message_OriginalFileName -ne "?"} |  group-object Message_Image,Message_OriginalFileName | sort-object -property count -Descending | format-table count,@{Label="Message_OriginalFileName"; Expression={($_.Name -split ",")[1]}},@{Label="Message_Image"; Expression={($_.Name -split ",")[0]}} -wrap
	
	"`n=========================================================================================="
	"Sysmon Registry Events containing key words in the registry path"
	"Key words: $SuspiciousRegNames"
	"=========================================================================================="	
	$AllSysmonEvents | where-object {($_.id -eq 12 -or $_.id -eq 13 -or $_.id -eq 14) -and $_.Message_TargetObject -match $SuspiciousRegNames } | format-table Message_utcTime,Message_Image,Message_EventType,Message_TargetObject -wrap
		
	"`n=========================================================================================="
	"Sysmon Event ID 1 (Process Create) Events where the Parent Commandline contains winword.exe, "
	"excel.exe, powerpoint.exe, mspub.exe, outlook.exe, visio.exe, etc. and the created "
	"process commandline contains jsc.exe, csc.exe, cmd.exe, powershell.exe, or msbuild.exe"
	"=========================================================================================="
	$AllSysmonEvents | where-object {$_.id -eq 1 } | Check-ParentChild | format-list Message_ParentProcessID,Message_ParentCommandLine,Message_ProcessID,Message_CommandLine

}

function Find-Suspiciouswords{
	#Look for Suspicious words in the message field of events 
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"============================= Suspicious Words found in Event Message ============================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"
	if ($SuspiciousWordsFile){
		$SuspiciouswordsRegex = Get-RegexFromWords -file $SuspiciousWordsFile -Separator '|'
		"#### Looking for these Suspicious words: " 
		"#### " + $SuspiciouswordsRegex.tostring()
		"######################################################"

		Foreach ($Event in $AllEvents) {
			if ($Event.Message) {
				if ( ($Event.Message).toLower() -match $SuspiciouswordsRegex) {
					"`n---------------------------------------------------------------------------------------------------"
					"######################################################"
					"#### Matched words:"
					"#### "+ $Matches.values
					"######################################################"
					"`nEvent Details:"
					$Event
				}
			}
		}
	
	} else {
		"`n`nNo Suspicious Words file provided"
	}
	

}

function Get-CommandlineAnalysis {
	param (
		$AllID1s
	)	
	
	if ($CmdLineWhitelistFile ) {
		$CmdLineWhitelist = Get-RegexFromWords -file $CmdLineWhitelistFile -Separator "|"
	} else {
		$CmdLineWhitelist = '.^'
	}
	

	"`n`n---------------------------------------------------------------------------------------------------"
	"-- All Command Lines recorded by Sysmon Event 1 by length in groups of 100, excludes Command Line  "
	"whitelist file entries"
	"---------------------------------------------------------------------------------------------------" 	
	
	#$AllID1 | where-object {$_.Message_CommandLine -notmatch $CmdLineWhitelist } | group-object -property Message_CommandLine | sort-object {($_.Name).length} -Descending | format-table @{Label="CommandLine Length"; Expression={($_.Name).length}},count
	
	$AllID1 | where-object {$_.Message_CommandLine -notmatch $CmdLineWhitelist } | group-object -property {[Int][Math]::Floor($_.Message_CommandLine.length / 100)} |sort-object -property name | ft @{Label="Start"; Expression={([int]$_.Name * 100)}},@{Label="End"; Expression={([int]$_.Name * 100 + 99)}},count 

	"`n`n---------------------------------------------------------------------------------------------------"
	"-- All Command Lines recorded by Sysmon Event 1 that match provided Suspicious "
	"Regular Expressions"
	"---------------------------------------------------------------------------------------------------" 	
	if ($SuspiciousRegexFile) {
		$SuspiciousRegex = (Get-content $SuspiciousRegexFile).split("`n")
		Foreach ($Event in $AllID1) {
			Foreach ($regex in $SuspiciousRegex){
				if ($Event.Message_CommandLine -match $regex) {
					$Event.Message_CommandLine
				}
			}
		} 	
	} else {
		"`nNo Suspicious Regular Expressions provided"
	}
	"`n`n---------------------------------------------------------------------------------------------------"
	"-- All Command Lines recorded by Sysmon Event 1 that are longer than 1000 characters, excludes"
	"   Command Line whitelist file entries"
	"---------------------------------------------------------------------------------------------------" 
	Foreach ($Event in $AllID1) {
		if (($Event.Message_CommandLine).length -gt 1000 -and $Event.Message_CommandLine -notmatch $CmdLineWhitelist ) {
			$Event.Message_CommandLine
		}
	}
	
}

function Get-Commandlines {
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"================================ Sysmon Process Create Commandlines ==============================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"
	


	$AllID1 = $AllSysmonEvents | where-object {$_.id -eq 1 -and $_.Message_CommandLine -ne $null } 

	Get-CommandlineAnalysis($AllID1) | write-output | out-file $CmdlineAnalysisOutputFile -encoding utf8
	
	
	"`n`n---------------------------------------------------------------------------------------------------"
	"-- All Command Lines recorded by Sysmon Event 1 (Process Create Events), grouped by image" 
	"---------------------------------------------------------------------------------------------------" 	
	$AllID1 | sort-object -property Message_Image | format-list Message_Image,Message_User,Message_LogonID,Message_ParentCommandLine,Message_CommandLine -groupby Message_image 
	
	
	
	
}

function Get-FileHashes {
 	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"================================== Sysmon Recorded File Hashes ==============================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 1 (Process Create Events) - Quick View" 
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 1 |group-object -property Message_image,Message_FileVersion,Message_hashes | sort-object -property count -Descending | format-table count,@{Label="Message_Image"; Expression={(($_.Name -split ',')[0] -split '\\')[-1]}},@{	Label="Message_FileVersion"; Expression={($_.Name -split ',')[1]}},@{Label="Message_Hash"; Expression={($_.Name -split ',')[2]}}

	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 1 (Process Create Events) - Detailed View"
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 1 |sort-object -property @{Expression={($_.Message_Image -split '\\')[-1]}},Message_Hashes -unique | format-list @{Label="Message_Image"; Expression={($_.Message_Image -split '\\')[-1]}},Message_Image,@{Label="Message_Hash-SHA1"; Expression={($_.Message_Hashes -split ',')[0]}},@{Label="Message_Hash-MD5"; Expression={($_.Message_Hashes -split ',')[1]}}, @{Label="Message_Hash-SHA256"; Expression={($_.Message_Hashes -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 7 (Image Loaded Events) - Quick View"
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 7 |group-object -property Message_imageLoaded,Message_FileVersion,Message_hashes | sort-object -property count -Descending | format-table count,@{Label="Message_ImageLoaded"; Expression={(($_.Name -split ',')[0] -split '\\')[-1]}},@{Label="Message_FileVersion"; Expression={($_.Name -split ',')[1]}},@{Label="Message_Hash"; Expression={($_.Name -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 7 (Image Loaded Events) - Detailed View"
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 7 |sort-object -property @{Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_Hashes -unique | format-list @{Label="Message_ImageLoaded"; Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_ImageLoaded,@{Label="Message_Hash-SHA1"; Expression={($_.Message_Hashes -split ',')[0]}},@{Label="Message_Hash-MD5"; Expression={($_.Message_Hashes -split ',')[1]}}, @{Label="Message_Hash-SHA256"; Expression={($_.Message_Hashes -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 6 (Kernel Driver Loaded Events) - Quick View "
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 6 |group-object -property Message_imageLoaded,Message_FileVersion,Message_hashes | sort-object -property count -Descending | format-table count,@{Label="Message_ImageLoaded"; Expression={(($_.Name -split ',')[0] -split '\\')[-1]}},@{Label="Message_FileVersion"; Expression={($_.Name -split ',')[1]}},@{Label="Message_Hash"; Expression={($_.Name -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 6 (Kernel Driver Loaded Events) - Detailed View" 
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 6 |sort-object -property @{Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_Hashes -unique | format-list @{Label="Message_ImageLoaded"; Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_ImageLoaded,@{Label="Message_Hash-SHA1"; Expression={($_.Message_Hashes -split ',')[0]}},@{Label="Message_Hash-MD5"; Expression={($_.Message_Hashes -split ',')[1]}}, @{Label="Message_Hash-SHA256"; Expression={($_.Message_Hashes -split ',')[2]}}
}
 
write-host "[] Writing Summary Analysis output to $SummaryAnalysisOutputFile" -foregroundcolor cyan
Get-SummaryAnalysis | write-output | out-file $SummaryAnalysisOutputFile -encoding utf8
write-host "[] Writing Logon Analysis output to $LogonAnalysisOutputFile" -foregroundcolor cyan
Get-LogonAnalysis | write-output | out-file $LogonAnalysisOutputFile -encoding utf8
write-host "[] Writing Sysmon Analysis output to $SysmonAnalysisOutputFile" -foregroundcolor cyan
Get-SysmonAnalysis | write-output | out-file $SysmonAnalysisOutputFile -encoding utf8
write-host "[] Writing Additional Analysis output to $AdditionalAnalysisOutputFile" -foregroundcolor cyan
Get-AdditionalAnalysis | write-output | out-file $AdditionalAnalysisOutputFile -encoding utf8
write-host "[] Writing Suspicious Word Match output to $SuspiciousWordMatchOutputFile" -foregroundcolor cyan
Find-Suspiciouswords | write-output | out-file $SuspiciousWordMatchOutputFile -encoding utf8
write-host "[] Writing Sysmon Recorded File Hashes to $FileHashesOutputFile" -foregroundcolor cyan
Get-FileHashes | write-output | out-file $FileHashesOutputFile -encoding utf8
write-host "[] Writing Sysmon Process Create Command Lines to $CmdlineOutputFile" -foregroundcolor cyan
Get-Commandlines | write-output | out-file $CmdlineOutputFile -encoding utf8


$ProcessingTime = ($(get-date) - $timestart)
write-host "[] Script Complete. Processing Time (hr:min:sec:ms) : $ProcessingTime  " -foregroundcolor cyan

"`n`n"