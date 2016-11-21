<#
    .Synopsis
        This script will create a baseline of a server and write an event to the security log if 
		it detects a change.
    .Description
        This script is meant to be run as a scheduled task on the domain controller.
		
    .Example
        ./Baseline-server.ps1 -domain domain.com 
		
    .Notes
        NAME: ./Baseline-server.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.00
        LASTEDIT: 20 NOV 2016
        CHANGELOG:
            1.00 - initial script 
    
        Output Colors:
        White - Input Required
        Cyan - Informational
        Yellow - Warning
        Red - Error

#>

$filename = $env:computername + ".txt"
$baseline = $env:Computername + "_baseline.txt"

" " | out-file $filename -append
"********************************************  Users" | out-file $filename -append
get-wmiobject -class Win32_useraccount | select -property caption | out-file $filename -append


" "| out-file $filename -append

"********************************************  Groups" | out-file $filename -append
Get-WmiObject -Class Win32_Group | select -property domain,name |out-file $filename -append


" "| out-file $filename -append
"********************************************  Groups and users" | out-file $filename -append
$ug = Get-WmiObject -Class Win32_GroupUser | select -Property groupcomponent,partcomponent 

foreach ($g in $ug) 
{
	$gp = $g.groupcomponent.tostring().split(',')[1]
	$u = $g.partcomponent.tostring().split(',')[1] 
	write-output "Group $gp   User $u" | out-file $filename -append
}


" "| out-file $filename -append
"********************************************  Shares" | out-file $filename -append
get-smbshare | out-file $filename -append


" "| out-file $filename -append
"********************************************  Registry keys" | out-file $filename -append
get-childitem HKLM:\software\Microsoft\Windows\CurrentVersion\Run | out-file $filename -append
get-childitem HKCU:\software\Microsoft\Windows\CurrentVersion\Run | out-file $filename -append

" "| out-file $filename -append
"********************************************  Scheduled Tasks" | out-file $filename -append
$tasks = schtasks /FO CSV /NH
$obj = convertfrom-csv $tasks -header task,nextruntime,status
foreach ($o in $obj)
{
	$o.status +"   " + $o.task | out-file $filename -append
}


" "| out-file $filename -append
"********************************************  Startup List" | out-file $filename -append
wmic startup list full | out-file $filename -append
" "| out-file $filename -append
"********************************************  Started Services" | out-file $filename -append
net start | out-file $filename -append

# compare file to baseline
if (test-path $baseline)
{
	$a = Get-Content $baseline
    $b = Get-Content $filename
	$results = compare-object  $a $b -passthru
	foreach($result in $results)
	{
		if ($result.sideindicator -eq "<=")
		{
			"In Baseline: "+ $result.tostring() | out-file 1SECURITY_GROUP_MODIFICATION.txt -append
			$message = "In Baseline: "+ $result.tostring()
			write-eventlog -logname application -source "EMET" -EventID 1111 -EntryType FailureAudit -Message $message
		} 
		else
		{
			"Not in Baseline: " + $result.tostring() | out-file 1SECURITY_GROUP_MODIFICATION.txt -append
			$message = "Not in Baseline: "+ $result.tostring()
			write-eventlog -logname application -source "EMET" -EventID 2222 -EntryType FailureAudit -Message $message
		}
	}
	
} 
else 
{
	rename-item -path $filename -newname $baseline
}

if (test-path $filename)
{
	remove-item -path $filename
}
