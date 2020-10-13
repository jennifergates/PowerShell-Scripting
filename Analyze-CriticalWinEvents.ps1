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


#------------------------- REGEX Definitions ------------------------------
#[regex]$Fields4624 = ".*Subject:\s*\n\s*Security ID:\s*(?<SecID>[^\n]*)\s*\n\s*Account Name:\s*(?<AcctName>[^\n]*)\n.*\n.*\n.*\nLogon Information:\s*\n\s*Logon Type:\s*(?<LogonType>[0-9]+).*\n.*\n.*\n.*\n.*\n.*\n.*\n.*New Logon:\s*Security ID:\s*(?<NewLogonSecID>[^\n]*)\n\s*Account Name:\s*(?<NewLogonAcctName>[^\n]*)\n\s*Account Domain:\s*(?<NewLogonAcctDom>[^\n]*)\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\s*Workstation Name:\s*(?<NetInfoWksName>[^\n]*)\s*\n\s*Source Network Address:\s*(?<NetInfoSrcAddr>[^\n]*)\s*\n\s*Source Port:\s*(?<NetInfoSrcPort>[^\n]*)\s*\n\s*\n\s*Detailed Authentication Information:\s*\n\.*\s*.*\n\s*Authentication Package:\s*(?<AuthPkg>[^\n]*).*\s*.*\s*Package Name \(NTLM only\):\s*(?<NTLMPkgName>[^\n]).*"

[regex]$Fields4624 = ".*Subject:\s*\n\s*Security ID:\s*(?<SecID>[^\n]*)\s*\n\s*Account Name:\s*(?<AccName>[^\n]*)\n.*\n\s*Logon ID:\s*(?<LogonID>[^\n]*)\s*\n.*\nLogon Information:\s*\n\s*Logon Type:\s*(?<LogonType>[0-9]+).*\n.*\n.*\n.*\n.*\n.*\n.*\n.*New Logon:\s*Security ID:\s*(?<NewLogonSecID>[^\n]*)\n\s*Account Name:\s*(?<NewLogonAcctName>[^\n]*)\n\s*Account Domain:\s*(?<NewLogonAcctDom>[^\n]*)\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\s*Workstation Name:\s*(?<NetInfoWksName>[^\n]*)\s*\n\s*Source Network Address:\s*(?<NetInfoSrcAddr>[^\n]*)\s*\n\s*Source Port:\s*(?<NetInfoSrcPort>[^\n]*)\s*\n\s*\n\s*Detailed Authentication Information:\s*\n\.*\s*.*\n\s*Authentication Package:\s*(?<AuthPkg>[^\n]*).*\s*.*\s*Package Name \(NTLM only\):\s*(?<NTLMPkgName>[^\n]).*"

[regex]$Fields4634 = ".*Subject:\s*\n\s*Security ID:\s*(?<SecID>[^\n]*)\s*\n\s*Account Name:\s*(?<AccName>[^\n]*)\n.*\n\s*Logon ID:\s*(?<LogonID>[^\n]*)\s*\n.*\n\s*Logon Type:\s*(?<LogonType>[0-9]+).*"

#------------------------- function ------------------------------
function Get-VarFromRegex {

param (
	[string]$EventID,
	[string]$EventMessage,
	[regex]$VarRegex
)
	#return [regex]::Match($EventMessage, $VarRegex)#.captures.groups
	$m = $VarRegex.match($EventMessage)

	$ret = new-Object -TypeName psobject
	$ret | Add-Member -MemberType NoteProperty -Name EventID -Value $EventID
	foreach ($var in $m.groups) {
		if ($var.name -ne 0 ){
			$ret | Add-Member -MemberType NoteProperty -Name $var.name -Value $var.value
		}
	}
	return $ret

}



#-------------------------------- Main --------------------------------#

# Read in all files to create one array of all event objects
write-host "[] Reading in files from $InputDirectory . `nDepending on the number and size of files, this could take a few minutes." -foregroundcolor cyan

$AllEventFiles = get-childitem $InputDirectory

$ListOfFileEventLists= foreach ($EventFile in $AllEventFiles){ get-content $EventFile.FullName | convertfrom-json}
$AllEvents = foreach ($FileEventList in $ListOfFileEventLists) { $FileEventList }

# Get details from Event 4624 Message fields
$All4624Messages = $AllEvents | where-object -property id -eq 4624 | select-object -property message -expandproperty message
$All4624Details = foreach ($EventMessage in $All4624Messages ){
	Get-VarFromRegex -EventMessage $EventMessage -VarRegex $Fields4624 -EventID 4624
}

# Get details from Event 4625 Message fields
$All4625Messages = $AllEvents | where-object -property id -eq 4625 | select-object -property message -expandproperty message
$All4625Details = foreach ($EventMessage in $All4625Messages ){
	Get-VarFromRegex -EventMessage $EventMessage -VarRegex $Fields4624 -EventID 4625
}

# Get details from Event 4634 Message fields
$All4634Messages = $AllEvents | where-object -property id -eq 4634 | select-object -property message -expandproperty message
$All4634Details = foreach ($EventMessage in $All4634Messages ){
	Get-VarFromRegex -EventMessage $EventMessage -VarRegex $Fields4634 -EventID 4634
}

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
	$AllEvents | Group-Object -Property message | sort-object -Property count -Descending | format-table Count,@{Label="Message"; Expression={$_.Name}} -Autosize
	"`n`n"
	"`n============================================================================="
	"Number of Event ID 4624 Events by Logon Type, New Logon Account Name, and Network Info Source Address:"
	"============================================================================="
	$All4624Details | group-object -property LogonType,NewLogonAcctName,NetInfoSrcAddr | sort-object -Property count -Descending | format-table Count,@{Label="LogonType, NewLogonAcctName, NetInfoSrcAddr"; Expression={$_.Name}} -wrap

	"`n============================================================================="
	"Number of Event ID 4624, Logon Type 3 Events by Auth Package, New Logon Account 
	Name, and New Logon Account Domain (Possible Successful Pass-The-Hash Indicator):"
	"============================================================================="
	
	$All4624Details | where-object -property LogonType -eq 3 | group-object -property AuthPkg,NewLogonAcctName,NewLogonAcctDom | sort-object -Property count -Descending| format-table Count,@{Label="Authpkg, NewLogonAcctName, NewLogonAcctDom"; Expression={$_.Name}} -wrap

	"`n============================================================================="
	"Number of Event ID 4625, Logon Type 3 Events by Auth Package, New Logon Account 
	Name, and New Logon Account Domain (Possible Failed Pass-The-Hash Indicator):"
	"============================================================================="

	$All4625Details | where-object -property LogonType -eq 3 | group-object -property AuthPkg,NewLogonAcctName,NewLogonAcctDom | sort-object -Property count -Descending| format-table Count,@{Label="Authpkg, NewLogonAcctName, NewLogonAcctName"; Expression={$_.Name}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 4624 Logon Type 10 Events by New Logon Account Name, and 
	Network Info Source Address (Remote Desktop Logon):"
	"============================================================================="
	$All4624Details | where-object -property LogonType -eq 10 | group-object -property NewLogonAcctName,NetInfoSrcAddr | sort-object -Property count -Descending | format-table Count,@{Label="NewLogonAcctName, NetInfoSrcAddr"; Expression={$_.Name}} -wrap
	
	"`n============================================================================="
	"Number of Event ID 4634 Logon Type 10 Events by Account Name, and Logon ID:"
	"============================================================================="
	$All4634Details | where-object -property LogonType -eq 10 | group-object -property AccName,LogonID | sort-object -Property count -Descending | format-table count,@{Label="Account Name, LogonID"; Expression={$_.Name}} -wrap
	
	#need to add the corresponding 4624 rdp logons for these logoffs.
}

 
write-host "[] Writing output to $OutputFile" -foregroundcolor cyan
Write-ToFile | write-output | out-file $OutputFile -encoding utf8


