<#
    .Synopsis
        This script will create a baseline of the local machine and write the output to a file.
    .Description
        This script will enumerate the System date and time, Hostname, User accounts and groups,
		Logged on users, Running processes, Services and their states, Network information,
		Listening network sockets, System configuration information, Mapped drives, Configured 
		devices, Shared resources, and Scheduled tasks. It will write the data to a files named
		Hostname_baseline_yyyyMMdd_HHmmss.txt and Hostname_baseline_yyyyMMdd_HHmmss.xml.
		
    .Example
        ./Gates_enum-LocalMachine.ps1 
		
    .Notes
        Enumerate baseline
        AUTHOR: Jennifer Gates
		
#>

#----------------------------------- Functions  ---------------------------------------------->
function WriteToFile ($obj) {
	foreach ( $noteproperty in $obj.psobject.properties) {
		write-output "`n-----------------------$($noteproperty.name)---------------------------------`n" 
		write-output $noteproperty.value
	}
}
#----------------------------------- Variables  ---------------------------------------------->
$daterun = $(get-date -Format "yyyyMMdd_HHmmss")
$hostname = "$env:computername"
#$filename = "$($hostname)_baseline_$($daterun)"
$filename = "objectify"
write-host "REMEMBER TO REMOVE THIS FILE RENAME COMMENT WHEN SUBMITTING!!!" -foregroundcolor red

$computerobj = new-object -TypeName PSObject
	$computerobj | add-member -membertype noteproperty -name Hostname -Value $hostname
	$computerobj | add-member -membertype noteproperty -name EnumDTG -Value $daterun
	$computerobj | add-member -membertype noteproperty -name RunningProcs -Value $(get-wmiobject win32_process | select name,processid,parentprocessid )
	$computerobj | add-member -membertype noteproperty -name Services -Value $(get-service | select Name,status,starttype )
	$computerobj | add-member -membertype noteproperty -name TCPListeningPorts -Value $(Get-NetTCPConnection | select LocalAddress,LocalPort,State,OwningProcess | where {$_.state -eq "Listen"}  |sort localport )
	$computerobj | add-member -membertype noteproperty -name UDPListeningPorts -Value $(Get-NetUDPEndpoint | select localaddress,localport,owningprocess | sort localport )
	$computerobj | add-member -membertype noteproperty -name ConfigInfoOS -Value $(Get-CIMInstance Win32_OperatingSystem | select Caption,InstallDate,Version,ServicePackMajorVersion,BuildNumber,BootDevice )
	$computerobj | add-member -membertype noteproperty -name ConfigInfoBIOS -Value $(Get-WmiObject win32_bios )
	$computerobj | add-member -membertype noteproperty -name ConfigInfoENV -Value $(get-childitem env:\ )
#----------------------------------- Script	    ---------------------------------------------->

WriteToFile($computerobj) | out-file "$filename.txt"
$computerobj | export-clixml "$filename.xml"