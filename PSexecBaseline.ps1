<#
    .Synopsis
        This script will create a baseline of a remote system using psexec to run commands on the system
    .Description
        This script takes a domain name and prompts for user's credentials to pull computers from the domain to baseline.
		
		This script relies in the RSAT tools for both the Import and the Get-ADComputer calls to work properly.
		
		If a baseline file is entered on the command line, it compares the output from each computer against
		it. If not, it looks for the last baseline for that computer to compare to. If no baseline exists, it renames
		this run's files to the baseline. 
		
		This script looks for the commands to run in a file called Psexec_Baseline_Tests.txt.
		
		If there are differences between the baseline and the current run, a file is created called 
		1DOMAIN_COMPUTER_MODIFICATION.txt. In it contains what changed.
		
    .Example
        ./PSexecBaseline.ps1 -domain domain.com 
    .Example
        ./PSexecBaseline.ps1 -domain domain.com -base company_baseline.txt
    .Example
        ./PSexecBaseline.ps1 -domain domain.com -cmdfile PSexec_Baseline_tests.txt
    .Parameter domain
        AD domain to connect to. Default is "company.domain.com"
	.Parameter base
        name of baseline file to compare to. Default is "company_baseline.txt"
	.Parameter cmdfile
        name of file with commands for psexec to run. Default is "PSexec_Baseline_tests.txt"
    .Notes
        NAME: ./PSexecBaseline.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.00
        LASTEDIT: 19 NOV 2016
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
	[string] $domain = "Company.domain.com",
	
	[string] $base = "Company_baseline.txt",
	
	[string] $cmdfile = "Psexec_Baseline_Tests.txt"
)


#-------------------------------- Variables --------------------------------#
Import-Module ActiveDirectory


$cred = get-credential
$pass = $cred.getnetworkcredential().password
$user = $cred.username


foreach ($remote in (Get-ADComputer -Filter 'ObjectClass -eq "Computer"' -server $domain | Select -Expand DNSHostName))
{

    if($base -eq $null)
    {
        $localbase = "$remote.baseline.txt"
    } else 
	{ 
		$localbase = $base 
	}
    $output = "$remote.temp.txt"
    if(Test-Path $output) { erase $output }
    foreach($item in Get-Content $cmdfile)
    {
		"__________________________________________________________________________" >> $output
		"Command: $item " >> $output
		"__________________________________________________________________________" >> $output

		& c:\tools\psexec.exe -accepteula \\$remote -u $user -p $pass cmd /c $item >> $output
    }
	#write-host $localbase
    if(test-path $localbase)
    {
        $a = Get-Content $localbase
        $b = Get-Content $output
				$results = compare-object  $a $b -passthru
		foreach($result in $results)
		{
			if ($result.sideindicator -eq "<=")
			{
				"ADDED $result.tostring()" | out-file 1DOMAIN_COMPUTER_MODIFICATION.txt -append
			} 
			else
			{
				"DELETED group $result.tostring()" | out-file 1DOMAIN_COMPUTER_MODIFICATION.txt -append
			}
		}
    }
    else
    {
        Write-Host "$remote has no baseline.  Assuming that this run should create the baseline." --foregroundcolor Yellow
        Rename-Item -path $output $localbase
    }
}