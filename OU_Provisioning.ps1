<#
    .SYNOPSIS
        This script reads Organizational Unit (OU) names from a file and creates a basic OU structure for each OU.
        
    .DESCRIPTION
        This script creates the OU, and sub OUs for OU_Servers, OU_Wkstns, OU_Groups, and OU_Users. In OU_Groups, it creates
        an OU_Users group, an OU_Wkstn_Admins group, and OU_Svr_Admins group. 
        
    .EXAMPLE
        ./OU_Provisioning.ps1 -file
        
    .PARAMETER file
        File path to text file that contains the desired OU names, one per line.
        
    .NOTES
        NAME: OU_provisioning.ps1
        AUTHOR: Jennifer Gates
        VERSION: .9
        LASTEDIT: 18 June 2017
        CHANGELOG:
            .9 (18 June 2017) - Initial Script.
            
#>

#----------------------------------- Parameters ---------------------------------------------->

Param(
    [string]$file
)


#----------------------------------- Functions  ---------------------------------------------->

Function Create-OUStructure
{
Param(
    [Parameter(mandatory=$true)]
    [string[]]$OUname
)

    New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -Name $OUName -Description "OU for $OUName"
    New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -Path "OU=$OUName,$($thisdomain.DistinguishedName)" -name "$OUName_Servers"
    New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -Path "OU=$OUName,$($thisdomain.DistinguishedName)" -name "$OUName_Wkstns"
    New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -Path "OU=$OUName,$($thisdomain.DistinguishedName)" -name "$OUName_Groups"
    New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -Path "OU=$OUName,$($thisdomain.DistinguishedName)" -name "$OUName_Users"
        
} #end function Create-OUStructure

Function Create-OUGroups
{
Param(
    [Parameter(mandatory=$true)]
    [string[]]$OUName
)

    New-ADGroup -Name "$OUName_Users" -GroupScope Global -Path "OU=$OUName,OU=$OUName_Groups,$($thisdomain.DistinguishedName)"
    New-ADGroup -Name "$OUName_Wkstn_Admins" -GroupScope Global -Path "OU=$OUName,OU=$OUName_Groups,$($thisdomain.DistinguishedName)"
    New-ADGroup -Name "$OUName_Svr_Admins" -GroupScope Global -Path "OU=$OUName,OU=$OUName_Groups,$($thisdomain.DistinguishedName)"
    New-ADGroup -Name "$OUAdmin_Workstations" -GroupScope Global -Path "OU=$OUName,OU=$OUName_Groups,$($thisdomain.DistinguishedName)"
} #end function Create-OUGroups

"Importing the Active Directory module...`n" | Write-Verbose
Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue | Out-Null 
Start-Sleep -Seconds 2  #Shouldn't be necessary, but seems to help avoid errors.


$curpref = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

"Switching to the AD:\ drive...`n" | Write-Verbose

cd AD:\
$thisdomain = Get-ADDomain -Current LocalComputer








