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
		
	.Parameter SuspiciousWordsFile
		Specifies a csv file that contains suspicious words to search for in the event message field.
		ex: 'whoami','ping','dsquery','dsget','tasklist','quser','cacls','wsmprovhost','psexec',
		
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
	
	[string] $SuspicousWordsFile = "SuspiciousWords.csv",
	
	[string] $OutputDirectory = "."
	
)


#-------------------------------- Input Verification --------------------------------#

$timestart = get-date
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

# ensure critical events file exists
if ($SuspiciousWordsFile -and (-not (test-path $SuspiciousWordsFile))) {
	write-host "$SuspiciousWordsFile does not exist. Please run again with a valid input directory." -foregroundcolor Red
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
$AnalysisOutputFile = $OutputDirectory + 'CriticalWinEventsAnalysis_' + $TimeRun + ".txt"
$SuspiciousWordMatchOutputFile = $OutputDirectory + 'SuspiciousWordMatches_' + $TimeRun + ".txt"
$FileHashesOutputFile = $OutputDirectory + 'SysmonRecordedFileHashes_' + $TimeRun + ".txt"
$CmdlineOutputFile = $OutputDirectory + 'SysmonProcessCreateCmdLines' + $TimeRun + ".txt"

$CriticalEvents = import-csv $CriticalEventsFile


#------------------------- REGEX Definitions ------------------------------#

[regex]$Fields4624 = ".*Subject:\s*\n\s*Security ID:\s*(?<SecID>[^\n]*)\s*\n\s*Account Name:\s*(?<AccName>[^\n]*)\n.*\n\s*Logon ID:\s*(?<LogonID>[^\n]*)\s*\n.*\nLogon Information:\s*\n\s*Logon Type:\s*(?<LogonType>[0-9]+).*\n.*\n.*\n.*\n.*\n.*\n.*\n.*New Logon:\s*Security ID:\s*(?<NewLogonSecID>[^\n]*)\n\s*Account Name:\s*(?<NewLogonAcctName>[^\n]*)\n\s*Account Domain:\s*(?<NewLogonAcctDom>[^\n]*)\n\s*Logon ID:\s*(?<NewLogonLogonID>[^\n]*)\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n\s*Workstation Name:\s*(?<NetInfoWksName>[^\n]*)\s*\n\s*Source Network Address:\s*(?<NetInfoSrcAddr>[^\n]*)\s*\n\s*Source Port:\s*(?<NetInfoSrcPort>[^\n]*)\s*\n\s*\n\s*Detailed Authentication Information:\s*\n\.*\s*.*\n\s*Authentication Package:\s*(?<AuthPkg>[^\n]*).*\s*.*\s*Package Name \(NTLM only\):\s*(?<NTLMPkgName>[^\n]).*"

[regex]$Fields4634 = ".*Subject:\s*\n\s*Security ID:\s*(?<SecID>[^\n]*)\s*\n\s*Account Name:\s*(?<AccName>[^\n]*)\n.*\n\s*Logon ID:\s*(?<LogonID>[^\n]*)\s*\n.*\n\s*Logon Type:\s*(?<LogonType>[0-9]+).*"




#------------------------- functions --------------------------------------#

function Get-VarsFromRegex {
	# Use Regular Expression to parse out additional details from the Message field of the event
	# and add them as additional properties to the event object for easier reporting
	param (
		$Event,
		[regex]$VarRegex
	)	
	$m = $VarRegex.match($Event.Message)

	$ret = $Event
	foreach ($var in $m.groups) {
		if ($var.name -ne $null ){
			$ret | Add-Member -MemberType NoteProperty -Name $var.name -Value $var.value
		}
	}
	return $ret

}

function Get-RegexFromWords {
	param (
		$File
	)
	$s = ""
	foreach ($line in (Get-content $File)) {
		
		$s = $s + $line.replace(',', '|').replace('/', '\/').replace('.', '\.').replace('(','\(').replace(')', '\)')
		$s = $s + '|'
	}
	$s  = $s -replace '.$'
	[regex]$s
}

#------------------------ Create Objects from Events with Message field details -----------------------------#

# Read in all files to create one array of all event objects
write-host "[] Reading in files from $InputDirectory . " -foregroundcolor cyan
write-host "`tDepending on the number and size of files, this could take a few minutes." -foregroundcolor yellow

$AllEventFiles = get-childitem $InputDirectory | where -property name -like '*.json'

$ListOfFileEventLists= foreach ($EventFile in $AllEventFiles){ get-content $EventFile.FullName | convertfrom-json}
$AllEvents = foreach ($FileEventList in $ListOfFileEventLists) { $FileEventList }

#### SECURITY EVENTS
# Get details from Event 4624 Message fields
$All4624Events = $AllEvents | where-object -property id -eq 4624 | foreach-object { 
	Get-VarsFromRegex -Event $_ -VarRegex $Fields4624
}

# Get details from Event 4625 Message fields
$All4625Events = $AllEvents | where-object -property id -eq 4625 | foreach-object { 
	Get-VarsFromRegex -Event $_ -VarRegex $Fields4624
}

# Get details from Event 4634 Message fields
$All4634Events = $AllEvents | where-object -property id -eq 4634 | foreach-object { 
	Get-VarsFromRegex -Event $_ -VarRegex $Fields4634
}


#### SYSMON EVENTS
# Create collection of new objects for each event where Sysmon message fields are their own properties in the object
$AllSysmonEvents = $AllEvents | where-object -property logname -eq "Microsoft-Windows-Sysmon/Operational" | foreach-object { 
	$NewEvent = $_
	foreach ($var in ($_.Message -split "`r`n" )) {
		$NewEvent |  Add-Member -MemberType NoteProperty -Name (('Message_'+$var -split ": ", 2)[0])  -Value ($var -split ": ", 2)[1]
	}
	$NewEvent
}

#------------------------ Use Objects to parse specifics from events -----------------------------#



# Get all registry key run key sysmon 12 events

# look for suspicious words  
function Find-Suspiciouswords{
	#Look for Suspicious words in the message field of events 
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"============================= Suspicious Words found in Event Message ============================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"
	if ($SuspiciousWordsFile){
		$SuspiciouswordsRegex = Get-RegexFromWords -file $SuspicousWordsFile
	} else {
		[regex]$SuspiciouswordsRegex = "whoami|ping|dsquery|dsget|tasklist|quser|cacls|wsmprovhost|psexec"
	}
	
	"#### Looking for these Suspicious words: " 
	"#### " + $SuspiciouswordsRegex.tostring()
	"######################################################"

	Foreach ($Event in $AllEvents) {
		if (($Event.Message).toLower() -match $SuspiciouswordsRegex) {
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


write-host "[] Calculating statistics" -foregroundcolor cyan

function Get-SummaryAnalysis {
	# Gather some basic statistics
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"======================== Critical Windows Events Analysis ==================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"

	"`n`n============================================================================="
	"The following files were analyzed: "
	"============================================================================="
	"Directory: $OutputDirectory "
	$AllEventFiles| format-table Name,LastWriteTime,Length
	"-----------------------------------------------------------------------------"
	"Total number of files: $($AllEventFiles.count)"
	"Total number of events: $($AllEvents.count)"

	"`n============================================================================="
	"Number of Events Retrieved by Event ID:"
	"============================================================================="
	$AllEvents | Group-Object -Property id,LogName | format-table @{Label="Logname"; Expression={($_.Name -split ",")[1]}},@{Label="EventID"; Expression={($_.Name -split ",")[0]}},Count
	"`n============================================================================="
	"Number of Events Retrieved by Log Name:"
	"============================================================================="
	$AllEvents | Group-Object -Property LogName | format-table @{Label="LogName"; Expression={$_.Name}},Count
	"`n============================================================================="
	"Number of Events Retrieved by Machine Name:"
	"============================================================================="
	$AllEvents | Group-Object -Property MachineName | format-table @{Label="MachineName"; Expression={$_.Name}},Count
	
	"`n`n"
	"`n============================================================================="
	"Number of Event ID 4624 Events by Logon Type, New Logon Account Name, and Network Info Source Address:"
	"============================================================================="
	$All4624Events | group-object -property LogonType,NewLogonAcctName,NetInfoSrcAddr | sort-object -Property count -Descending | format-table Count,@{Label="LogonType"; Expression={($_.Name -split ",")[0]}},@{Label="NewLogonAcctName"; Expression={($_.Name -split ",")[1]}},@{Label="NetInfoSrcAddr"; Expression={($_.Name -split ",")[2]}} -wrap
	

	"`n============================================================================="
	"Number of Event ID 4624, Logon Type 3 Events by Auth Package, New Logon Account 
	Name, and New Logon Account Domain (Possible Successful Pass-The-Hash Indicator):"
	"============================================================================="
	
	$All4624Events | where-object -property LogonType -eq 3 | group-object -property AuthPkg,NewLogonAcctName,NewLogonAcctDom | sort-object -Property count -Descending| format-table Count,@{Label="Authpkg"; Expression={($_.Name -split ",")[0]}},@{Label="NewLogonAcctName"; Expression={($_.Name -split ",")[1]}},@{Label="NewLogonAcctName"; Expression={($_.Name -split ",")[2]}} -wrap

	"`n============================================================================="
	"Number of Event ID 4625, Logon Type 3 Events by Auth Package, New Logon Account 
	Name, and New Logon Account Domain (Possible Failed Pass-The-Hash Indicator):"
	"============================================================================="

	$All4625Events | where-object -property LogonType -eq 3 | group-object -property AuthPkg,NewLogonAcctName,NewLogonAcctDom | sort-object -Property count -Descending| format-table Count,@{Label="Authpkg"; Expression={($_.Name -split ",")[0]}},@{Label="NewLogonAcctName"; Expression={($_.Name -split ",")[1]}},@{Label="NewLogonAcctName"; Expression={($_.Name -split ",")[2]}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 4624 Logon Type 10 Logon Events by Account Name, and Logon ID
	and Network Info Source Address (Remote Desktop Logon):"
	"============================================================================="
	$All4624Events | where-object -property LogonType -eq 10 | group-object -property NewLogonAcctName,NewLogonLogonID,NetInfoSrcAddr | sort-object -Property count -Descending | format-table count,@{Label="Account Name"; Expression={($_.Name -split ",")[0]}},@{Label="LogonID"; Expression={($_.Name -split ",")[1]}},@{Label="NetInfoSrcAddr"; Expression={($_.Name -split ",")[2]}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 4634 Logon Type 10 Logoff Events by Account Name, and Logon ID:"
	"============================================================================="
	$All4634Events | where-object -property LogonType -eq 10 | group-object -property AccName,LogonID | sort-object -Property count -Descending | format-table count,@{Label="Account Name"; Expression={($_.Name -split ",")[0]}},@{Label="LogonID"; Expression={($_.Name -split ",")[1]}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 10 (Process Access) Sysmon Events by Target Image with full path"
	"============================================================================="
	$AllSysmonEvents | where-object -property id -eq 10  | group-object -property Message_TargetImage | sort-object -Property count -Descending | format-table count,@{Label="Message_TargetImage"; Expression={$_.Name}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 10 (Process Access) Sysmon Events by Target Image"
	"============================================================================="	
	$AllSysmonEvents | where-object -property id -eq 10 |foreach-object { ($_.Message_TargetImage -split "\\")[-1] } | group-object | sort-object -property count -Descending | format-table count,@{Label="Message_TargetImage"; Expression={$_.Name}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 1 (Process Create) Sysmon Events where Image name doesn't equal Original File name"
	"============================================================================="	
	$AllSysmonEvents | where-object -property id -eq 1 | where-object { ($_.Message_Image -split("\\"))[-1] -ne $_.Message_OriginalFileName} |  group-object Message_Image,Message_OriginalFileName | sort-object -property count -Descending | format-table count,@{Label="Message_Image"; Expression={($_.Name -split ",")[0]}},@{Label="Message_OriginalFileName"; Expression={($_.Name -split ",")[1]}} -wrap
	

}

function Get-Commandlines {
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"================================ Sysmon Process Create Commandlines ==============================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"
	"---------------------------------------------------------------------------------------------------"
	"-- All Command Lines recorded by Sysmon Event 1 (Process Create Events)" 
	"---------------------------------------------------------------------------------------------------" 
	$AllSysmonEvents |where-object {$_.id -eq 1 -and $_.Message_CommandLine -ne $null } |sort-object -property Message_Image | format-list Message_Image,Message_User,Message_LogonID,Message_ParentCommandLine,Message_CommandLine -groupby Message_image 
}

 function Get-FileHashes {
 	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"================================== Sysmon Recorded File Hashes ==============================="
	"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	"`n Script Run Time: $TimeRun"
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 1 (Process Create Events) - Quick View" 
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 1 |group-object -property Message_image,Message_FileVersion,Message_hashes | sort-object -property name | format-table count,@{Label="Message_Image"; Expression={(($_.Name -split ',')[0] -split '\\')[-1]}},@{	Label="Message_FileVersion"; Expression={($_.Name -split ',')[1]}},@{Label="Message_Hash"; Expression={($_.Name -split ',')[2]}}

	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 1 (Process Create Events) - Detailed View"
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 1 |sort-object -property @{Expression={($_.Message_Image -split '\\')[-1]}},Message_Hashes -unique | format-list @{Label="Message_Image"; Expression={($_.Message_Image -split '\\')[-1]}},Message_Image,@{Label="Message_Hash-SHA1"; Expression={($_.Message_Hashes -split ',')[0]}},@{Label="Message_Hash-MD5"; Expression={($_.Message_Hashes -split ',')[1]}}, @{Label="Message_Hash-SHA256"; Expression={($_.Message_Hashes -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 7 (Image Loaded Events) - Quick View"
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 7 |group-object -property Message_imageLoaded,Message_FileVersion,Message_hashes | sort-object -property name | format-table count,@{Label="Message_ImageLoaded"; Expression={(($_.Name -split ',')[0] -split '\\')[-1]}},@{Label="Message_FileVersion"; Expression={($_.Name -split ',')[1]}},@{Label="Message_Hash"; Expression={($_.Name -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 7 (Image Loaded Events) - Detailed View"
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 7 |sort-object -property @{Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_Hashes -unique | format-list @{Label="Message_ImageLoaded"; Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_ImageLoaded,@{Label="Message_Hash-SHA1"; Expression={($_.Message_Hashes -split ',')[0]}},@{Label="Message_Hash-MD5"; Expression={($_.Message_Hashes -split ',')[1]}}, @{Label="Message_Hash-SHA256"; Expression={($_.Message_Hashes -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 6 (Kernel Driver Loaded Events) - Quick View "
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 6 |group-object -property Message_imageLoaded,Message_FileVersion,Message_hashes | sort-object -property name | format-table count,@{Label="Message_ImageLoaded"; Expression={(($_.Name -split ',')[0] -split '\\')[-1]}},@{Label="Message_FileVersion"; Expression={($_.Name -split ',')[1]}},@{Label="Message_Hash"; Expression={($_.Name -split ',')[2]}}
	
	"---------------------------------------------------------------------------------------------------"
	"-- All files with recorded hashes by Sysmon Event 6 (Kernel Driver Loaded Events) - Detailed View" 
	"---------------------------------------------------------------------------------------------------"
	$AllSysmonEvents | where-object -property id -eq 6 |sort-object -property @{Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_Hashes -unique | format-list @{Label="Message_ImageLoaded"; Expression={($_.Message_ImageLoaded -split '\\')[-1]}},Message_ImageLoaded,@{Label="Message_Hash-SHA1"; Expression={($_.Message_Hashes -split ',')[0]}},@{Label="Message_Hash-MD5"; Expression={($_.Message_Hashes -split ',')[1]}}, @{Label="Message_Hash-SHA256"; Expression={($_.Message_Hashes -split ',')[2]}}
}
 
write-host "[] Writing Analysis output to $AnalysisOutputFile" -foregroundcolor cyan
Get-SummaryAnalysis | write-output | out-file $AnalysisOutputFile -encoding utf8
write-host "[] Writing Suspicious Word Match output to $SuspiciousWordMatchOutputFile" -foregroundcolor cyan
Find-Suspiciouswords | write-output | out-file $SuspiciousWordMatchOutputFile -encoding utf8
write-host "[] Writing Sysmon Recorded File Hashes to $FileHashesOutputFile" -foregroundcolor cyan
Get-FileHashes | write-output | out-file $FileHashesOutputFile -encoding utf8
write-host "[] Writing Sysmon Process Create Command Lines to $CmdlineOutputFile" -foregroundcolor cyan

Get-Commandlines | write-output | out-file $CmdlineOutputFile -encoding utf8


$ProcessingTime = ($(get-date) - $timestart).TotalMinutes
write-host "[] Script Complete. Processing Time (in minutes): $ProcessingTime  " -foregroundcolor cyan

"`n`n"