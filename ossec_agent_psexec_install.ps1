<#
    .Synopsis
        This script will install the ossec agent on a remote system using psexec to run commands on the system
    .Description
        This script takes an input file that lists the windows computers by IP and hostname. It also requires the 
		path to client.keys files for each computer on the list. It also 
		
		The script installs the Windows OSSEC agent silently, copies the host's <hostname>_client.keys and ossec.conf 
		files to the program's folder, and then starts the ossec agent service.
		
    .Example
        ./ossec_agent_psexec_install.ps1 -computers_file mycomputers.txt -keys C:\ossec_keys\ -exe ossec-agent-win32-2.8.3.exe 
		-config ossec.config

    .Parameter computers_file
        file with list of computer IPs and hostnames to install the agent onto
	.Parameter keys
        path to the <hostname>_client.keys files
	.Parameter exe
        ossec agent installer file
	.Parameter config
        path to the ossec config file
    .Notes
        NAME: ./ossec_agent_psexec_install.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.00
        LASTEDIT: 20 April 2017
        CHANGELOG:
            1.00 - initial script 
    
        Output Colors:
        White - Input Required
        Cyan - Informational
        Yellow - Warning
        Red - Error

#>
#-------------------------------- Parameters --------------------------------#

Param(
	[Parameter(Mandatory=$True)]
	[string] $computers_file,
	
	[Parameter(Mandatory=$True)]
	[string] $keys,
	
	[Parameter(Mandatory=$True)]
	[string] $exe,
	
	[Parameter(Mandatory=$True)]
	[string] $config
)


#-------------------------------- Variables --------------------------------#


$cred = get-credential
$pass = $cred.getnetworkcredential().password
$user = $cred.username
$output = "ossec_installs.txt"

#Check if input file exists. Exit if not.
$FileExists = Test-Path $computers_file
if($FileExists -eq $False) {
	write-host "$computers_file does not exist." 
	exit
} 

#import computer hostname,IP from input file	
$computers = (Get-Content $computers_file)
#write-host $computers[0]

# loop through each computer and install ossec agent, copy files, start service
foreach ($remote in $computers)
{
	$remote = $remote.split(",")
	$hostname = $remote[0]
	$ip = $remote[1]
	$keyfile = $hostname + "_client.keys"
	#write-host $keyfile
	
	# install ossec-agent.exe
	"[ ] Installing on $ip with $hostname"
	"Installing on $ip with $hostname" | out-file $output -append
    	
	# test if already installed
	$FileExists =test-path "\\$ip\c$\program files (x86)\ossec-agent\ossec-agent.exe"
	if($FileExists -eq $True) {
		write-host "     $ip already has ossec-agent installed. Continuing." | out-file $output -append
	} else {
		& C:\Users\Administrator\Desktop\SysInternals\PsExec.exe \\$ip -u $user -p $pass -c ossec-agent-win32-2.8.3.exe /S -accepteula >> $output
	}
	
	# copy config file to correct location.
	"[ ] Copying $config"
	"Copying $config" | out-file $output -append
	copy-item -path "\\$ip\c$\program files (x86)\ossec-agent\ossec.conf" -destination "\\$ip\c$\program files (x86)\ossec-agent\ossec-conf.bak" -force >> $output
	
	copy-item -path $config -destination "\\$ip\c$\program files (x86)\ossec-agent\ossec.conf" -force >> $output
	
	# copy corresponding host client.keys file 
	if($keys.substring($keys.length-1) -eq "\") {
		$keys = $keys.substring(0,$keys.length-1)
		}
	
	$keyfile = $keys + "\" + $hostname + "_client.keys"
	"[ ] Copying $keyfile to $hostname"
	"Copying $keyfile to $hostname" | out-file $output -append
	copy-item -path $keyfile -destination "\\$ip\c$\program files (x86)\ossec-agent\client.keys" -force >> $output
	
	# start service
	"[ ] Starting ossec-agent service"
	"Starting ossec-agent service" | out-file $output -append
	get-service -computer $ip "OSSEC HIDS" | set-service -status running
	
	"____________________________________________" | out-file $output -append
}
