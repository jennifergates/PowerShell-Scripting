<#
    .Synopsis
        This script will create a baseline of the local machine and write the output to a file.
    .Description
        This script will enumerate the System date and time, Hostname, User accounts and groups,
		Logged on users, Running processes, Services and their states, Network information,
		Listening network sockets, System configuration information, Mapped drives, Configured 
		devices, Shared resources, and Scheduled tasks. 
		
		This script will obtain the most information when run as administrator.
		
		Details are written to a file named Hostname_baseline_yyyyMMdd_HHmmss.txt.
		
    .Example
        ./Gates_enum-LocalMachine.ps1 
		
    .Notes
        Exercise: 1. Enumerate baseline
        AUTHOR: Jennifer Gates
		
#>

#----------------------------------- Variables  ---------------------------------------------->
$daterun = get-date -Format "yyyy-MM-dd HH:mm:ss"
$filedate = (($daterun.ToSTring().replace(' ', '_')).replace('-', '')).replace(':', '')
$hostname = "$env:computername"
$filename = "$($hostname)_baseline_$($filedate).txt"

#----------------------------------- Templates  ---------------------------------------------->

$quser_template = @'
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>{Username*:gates}                 {Sessionname:console}             {ID:2}  {State:Active}    8+08:47  {LogonTime:9/24/2017 4:18 PM}
 {Username*:administrator}         {Sessionname:       }             {ID:4}  {State:Disc}      1+05:23  {LogonTime:9/27/2017 11:11 AM}
'@

#----------------------------------- Functions  ---------------------------------------------->
function Write-toFile () {
	"`n========================================================================="

	"CREATING BASELINE FOR HOST $($hostname)"
	"`n========================================================================="
	"`nHostname: $hostname "
	"Baseline Date: $daterun"

	"`n---------------------------USERS/GROUPS-----------------------------------"
	" "
	$(foreach ($user in $(get-localuser )) { $groups = getlocalgroupsforuser($user); "USER: $($user.name) IS IN LOCALGROUPS: $($groups -join ', ')"})

	"`n---------------------------CURRENTLY LOGGED ON USERS----------------------"
	$(Get-LoggedOnUsers | select Username,SessionName,ID,State,LogonTime | format-table)
	#$(Get-ciminstance win32_loggedonuser | select antecedent | foreach{ "{0}@{1} is currently logged on." -f $_.antecedent.name, $_.antecedent.domain})

	"`n---------------------------RUNNING PROCESSES------------------------------"
	$(get-wmiobject win32_process | select Name,ProcessID,ParentProcessID | format-table);

	"`n---------------------------SERVICES --------------------------------------"
	$(get-service | select ServiceName, StartType, Status | format-table);

	"`n---------------------------NETWORK CONFIGURATION INFORMATION--------------"
	"Network Configuration"
	$(Get-NetIPConfiguration )
	"Network Adapters:"
	$(Get-NetAdapter | select InterfaceDescription,MACaddress,MediaConnectionState,@{l='Promisc'; e={$_.PromiscuousMode}} | format-table)
	"IP Addresses:"
	$(Get-NetIPAddress | select InterfaceAlias,IPAddress | sort AddressFamily | format-table)

	"`n---------------------------LISTENING TCP SOCKETS--------------------------"
	$(Get-NetTCPConnection | select @{l='Proto';e={'TCP'}},LocalAddress,LocalPort,State,OwningProcess | where {$_.state -eq "Listen"}  |sort localport | format-table)

	"`n--------------------------- UDP OPEN PORTS--------------------------------"
	$(Get-NetUDPEndpoint | select @{l='Proto';e={'UDP'}},LocalAddress,LocalPort,OwningProcess | sort localport | format-table)

	"`n---------------------------SYSTEM CONFIGURATION INFORMATION---------------"
	$(Get-CIMInstance Win32_OperatingSystem | select Caption,InstallDate,Version,ServicePackMajorVersion,BuildNumber,BootDevice,SystemDevice,SystemDirectory,SystemDrive,WindowsDirectory,OSArchitecture | format-list)
	$(Get-WmiObject win32_bios | format-list)
	"Environment Variables   :"
	#get-childitem env:\ | format-table -wrap
	$(PathVarByRows)

	"`n---------------------------MAPPED DRIVES----------------------------------"
	$(Get-WmiObject -Class Win32_MappedLogicalDisk | select Name, ProviderName | format-list)

	"`n---------------------------CONFIGURED DEVICES-----------------------------"
	$(get-pnpdevice | select Present,Manufacturer,Name  | sort manufacturer | format-table -wrap)

	"`n---------------------------SHARED RESOURCES-------------------------------"
	$(Get-WmiObject win32_share | format-table)

	"`n---------------------------SCHEDULED TASKS--------------------------------"
	#$( get-scheduledtask | select taskname,triggers,state | sort taskname| format-table -wrap)
	$(EnumSchTask | select TaskName,ScheduleType,State | sort TaskName | format-table)
}
function GetLocalGroupsforUser($inuser) {
	$usergroups = @()
	$localgroups = Get-localgroup | select name
	foreach ($group in $localgroups) { 
		$members = get-localgroupmember $group.name | where {$_.objectclass -eq "User"} 
		if ($members.name -match $inuser.name ) {
			$usergroups += $group.name
		} 
	}
	return $usergroups
}
function EnumSchTask {
	$sch = schtasks /query /fo list /v
	$lines = $sch.split("`n")
	$objects = @()
	
	foreach ($line in $lines) {
		if ($line -match "TaskName:" ) {
			$taskobj = new-object -TypeName PSObject
			$taskobj | add-member -membertype noteproperty -name TaskName -Value "$((($line.split(':'))[1].trim().split('\'))[-1])"
		} elseif ($line -match "Author:") {
			$taskobj | add-member -membertype noteproperty -name Author -Value "$(($line.split(':'))[1].trim())"
		} elseif ($line -match "Task to Run:") {
			$taskobj | add-member -membertype noteproperty -name TaskToRun -Value "$(($line.split(':'))[1].trim())"
		} elseif ($line -match "Scheduled Task State:") {
			$taskobj | add-member -membertype noteproperty -name State -Value "$(($line.split(':'))[1].trim())"
		} elseif ($line -match "Run As User:") {
			$taskobj | add-member -membertype noteproperty -name RunAsUser -Value "$(($line.split(':'))[1].trim())"
		} elseif ($line -match "Schedule Type:") {
			$taskobj | add-member -membertype noteproperty -name ScheduleType -Value "$(($line.split(':'))[1].trim())"
			$objects += $taskobj
			$taskobj = new-object -TypeName PSObject
		}
	}
	return $objects
}

 Function Get-LoggedOnUsers {
	$quser = query user
	$quser | convertfrom-string -templatecontent $quser_template -outvariable loggedonusers | out-null
	return $loggedonusers
 }
 
 Function PathVarByRows {
	$pathrows = ($env:path).split(";")
	$pathrows = $pathrows | ?{$_ -ne ""}
	write-output "Environment Variable PATH:"
	foreach ($row in $Pathrows) { "PATH Entry $($pathrows.indexof($row) +1) - $row" }
}
 
#----------------------------------- Script	    ---------------------------------------------->
Write-toFile | write-output | out-file $filename  -encoding unicode
