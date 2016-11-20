<#
    .Synopsis
        This script checks for changes in group membership for a specified OU.
    .Description
        Script takes an Active Directory OU and returns a list of all groups within that OU and the members of those groups. 
		Then compares the two files and if changes, returns what changed. uses md5deep64.exe to hash files.
    .Example
        ./Get-AllGroupsMembers.ps1
    .Example
        ./Get-AllGroupsMembers.ps1 Security-Groups
    .Example
        ./Get-AllGroupsMembers.ps1 -ou Security-Groups
    .Parameter domain
        AD domain to connect to
	.Parameter OU
        OU that contains the groups
	.Parameter filename
        string to use as output file name
	.Parameter baseline
        name of baseline file to compare
    .Notes
        NAME: ./Get-AllGroupsMembers.ps1
        AUTHOR: Jennifer Gates
        VERSION: 1.00
        LASTEDIT: 19 NOV 2016
        CHANGELOG:
            1.00 - initial script - still need to fix comparison side indicator replacement (added/delete)
    
        Output Colors:
        White - Input Required
        Cyan - Informational
        Yellow - Warning
        Red - Error

#>

#-------------------------------- Parameters --------------------------------#

Param(
    [string] $ou = "Security_Groups",

	[string] $domain = "Company.domain.com",
	
	[string] $baseline = "Company_baseline.txt",
	
	[string] $filename = "Company_Security_Groups"
)


#-------------------------------- Variables --------------------------------#

Import-Module ActiveDirectory
$OUName = $ou
$OUObject = get-ADorganizationalUnit -server $domain -Filter 'Name -like $OUName' #| Format-list -property DistinguishedName
$DateFormatted = Get-date -uformat "%Y%m%d-%H%M"
$OutputFile = $filename + $DateFormatted + '.txt'

" "
" "
write-host "Getting groups in OU "  $OUObject.DistinguishedName 
write-host "Please wait for file " $outputfile  "to be created." -foregroundcolor Yellow
" "


# Gets all the groups in the OU and sorts them alphabetically
$SecGroups = Get-adobject -server $domain -Filter 'ObjectClass -eq "group"' -SearchBase $OUObject.DistinguishedName -properties *
$SecGroups = $SecGroups | sort-object name

#Goes through each group and prints the name and description
foreach ($SecGroup in $SecGroups) {

	
	$SecGroup.name | out-file $OutputFile -append
	"____________________________________________________________________________" | out-file $OutputFile -append
	
	#gets the members of the group, determines if user or another group nested and displays info about each member alphabetically
	$users = Get-ADGroupMember -server $domain -identity $SecGroup -recursive
	if ($users) {
		$users = $users | sort-object name
		foreach ($user in $users) {
			if ($user.objectclass -eq 'user') {
				$name = get-aduser -server $domain $user
				#write-host $name.GivenName $name.surname 
				#write-host $name.name $name.userprincipalname $name.sid
				#write-host $name.SID
				"     " + $SecGroup.name + ":   "+ $name.Name + " " + $name.userprincipalname  | out-file $OutputFile -append
			} 
			else {
				$group = get-adgroup $user
				"     " + $group.name | out-file $OutputFile -append
			}
		}	
	} 
	else {
		"     No direct members" | out-file $OutputFile -append
	}
		"    " | out-file $OutputFile -append
}


# compare file to baseline
if (test-path $baseline)
{
	$base = Invoke-Expression '.\md5deep64.exe $baseline'
	$now = Invoke-Expression '.\md5deep64.exe $outputfile'
	if ((compare-object $base $now).count -gt 0)
	{
	
		$a = Get-Content $baseline
        $b = Get-Content $outputfile
		$results = compare-object  $a $b -passthru
		foreach($result in $results)
		{
			if ($result.sideindicator -eq "<=")
			{
				"User DELETED to group $result.tostring()" | out-file 1SECURITY_GROUP_MODIFICATION.txt -append
			} 
			else
			{
				"User ADDED from group $result.tostring()" | out-file 1SECURITY_GROUP_MODIFICATION.txt -append
			}
		}
	}
	
} 
else 
{
	rename-item -path $outputfile -newname "Company_baseline.txt"
}
	
	
	
