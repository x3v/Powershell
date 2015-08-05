<#
Magi script 
Last edited 7/25/2015 
Created by Jonathan Zevallos
For additions, edits, questions, etc. 
See notes for all other scripting purposes. 
#>

do {
    do {
        write-host ""
        write-host "Is this setup for a new hire? [Y][N]"       
        write-host ""
        
        $choice = read-host
        
        write-host ""
        
        $ok = $choice -match '^[yn]+$'
        
        if ( -not $ok) { write-host "No records of that exists." }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
        "Y"
        {            
		Import-Module ActiveDirectory
		get-adcomputer $env:COMPUTERNAME | Move-ADObject -TargetPath 'OU=Laptops,OU=Deerfield,OU=Corporate,OU=Domain Users,DC=americas,DC=bgsw,DC=com' -Credential ""

		$User = New-Object System.Security.Principal.NTAccount($env:UserName)
		$sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
   	$shell = new-object -com "Shell.Application"  
		
		New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
		New-PSDrive -Name HKLM -PSProvider Registry -Root Registry::HKEY_LOCAL_MACHINE
		New-PSDrive -Name HKCU -PSProvider Registry -Root Registry::HKEY_CURRENT_USER

		New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\CSC\Parameters"  -Name FormatDatabase -Value 1 -Type DWord
		New-ItemProperty "HKCU:\Software\Microsoft\Office\15.0\Outlook\Preferences" -Name EmptyTrash -Value 1 -Type DWord
		New-ItemProperty "HKCU:\Software\Microsoft\Office\15.0\Common\Internet" -Name UseOnlineContent -Value 2 -Type DWord
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
		Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Name Persistent -Value 1

		#Pins applications to start menu. 
		$folder = $shell.Namespace('C:\Program Files\Microsoft Office 15\root\office15')    
		$folder2 = $shell.Namespace('C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client')    
		$item1 = $folder.Parsename('powerpnt.exe')
		$item2 = $folder.Parsename('lync.exe')
		$item3 = $folder.Parsename('OUTLOOK.exe')
		$item4 = $folder.Parsename('EXCEL.exe')
		$item5 = $folder.Parsename('WINWORD.exe')
		$item6 = $folder2.Parsename('vpnui.exe')
		$verb = $item1.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb2 = $item2.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb3 = $item3.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb4 = $item4.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb5 = $item5.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb6 = $item6.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		if ($verb) {$verb.DoIt()}
		if ($verb2) {$verb2.DoIt()}
		if ($verb3) {$verb3.DoIt()}
		if ($verb4) {$verb4.DoIt()}
		if ($verb5) {$verb5.DoIt()}
		if ($verb6) {$verb6.DoIt()}

		#Removes IE x64 from start menu, enables TRIM and sets to high power settings.
		Remove-Item $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Internet Explorer (64-bit).lnk"
		robocopy "C:\Windows\End.lnk" "C:\Users\jzevallos\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories" 
		
		fsutil behavior set DisableDeleteNotify 0
 	 	powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
		
    #Disables UAC, Creates new registry property for disabling IPv6 then deletes SchedulesDefrag schedule. 	
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
		New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' `
     			-Name  'DisabledComponents' -Value '0xffffffff' -PropertyType 'DWord'
		SchTasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F
		Disable-NetAdapterBinding -Name "Wi-Fi" -ComponentID ms_tcip6

		#Invokes SAP process for registry creation.  
		Start-Process "C:\Program Files (x86)\SAP\FrontEnd\SAPgui\sapfewcp.exe"
		Start-Sleep -s 3
		
		
		#Creates actual Security key, then security values. Closes SAP process after registry value is created.
		New-Item -Path "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server" -name Security
		New-ItemProperty "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server\Security\"  -Name SecurityLevel -Value 0 -Type DWord
		New-ItemProperty "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server\Security\"  -Name DefaultAction -Value 0 -Type DWord
		Stop-Process -processname sapsettingsshow

		Start-Process "C:\Program Files (x86)\McAfee\VirusScan Enterprise\mcupdate.exe"

		Start-Process "C:\Windows\Resources\Ease of Access Themes\basic.theme"
		Start-Sleep -s 2
		Stop-Process -processname explorer
		
        }
        
        "N"
        {
		$diskdrive = gwmi win32_diskdrive | ?{$_.interfacetype -eq "USB"}
		$letters = $diskdrive | %{gwmi -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  %{gwmi -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | %{$_. deviceid} 

		$drive = gwmi win32_volume | ? {$letters -contains ($_.name -replace "\\")}
		$drive.DriveLetter

		New-PSDrive -Name EXT -PSProvider FileSystem -Root $drive.DriveLetter

		cd "EXT:\Users\$env:username\"
		robocopy "Favorites" "$env:UserProfile\Favorites" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "Desktop" "$env:UserProfile\Desktop" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "Pictures" "$env:UserProfile\Pictures" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "Music" "$env:UserProfile\Music" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "Videos" "$env:UserProfile\Videos" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "Documents" "$env:UserProfile\Documents" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "AppData\Roaming\Microsoft\Signatures" "$env:UserProfile\AppData\Roaming\Microsoft\Signatures" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "AppData\Roaming\Microsoft\Templates" "$env:UserProfile\AppData\Roaming\Microsoft\Templates" /E /SEC /COPYALL /ZB /R:0 /W:0 /mir /np /xd /eta
		robocopy "AppData\Local\Microsoft\Outlook" "$env:UserProfile\AppData\Local\Microsoft\Outlook" *.pst
		
		Import-Module ActiveDirectory
		get-adcomputer $env:COMPUTERNAME | Move-ADObject -TargetPath 'DC=example,DC=com' -Credential ""

		$User = New-Object System.Security.Principal.NTAccount($env:UserName)
		$sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
   	$shell = new-object -com "Shell.Application"  
		
		New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
		New-PSDrive -Name HKLM -PSProvider Registry -Root Registry::HKEY_LOCAL_MACHINE
		New-PSDrive -Name HKCU -PSProvider Registry -Root Registry::HKEY_CURRENT_USER
		
		New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\CSC\Parameters"  -Name FormatDatabase -Value 1 -Type DWord
		New-ItemProperty "HKCU:\Software\Microsoft\Office\15.0\Outlook\Preferences" -Name EmptyTrash -Value 1 -Type DWord
		New-ItemProperty "HKCU:\Software\Microsoft\Office\15.0\Common\Internet" -Name UseOnlineContent -Value 2 -Type DWord
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

		#Pins applications to start menu. 
		$folder = $shell.Namespace('C:\Program Files\Microsoft Office 15\root\office15')    
		$folder2 = $shell.Namespace('C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client')    
		$item1 = $folder.Parsename('powerpnt.exe')
		$item2 = $folder.Parsename('lync.exe')
		$item3 = $folder.Parsename('OUTLOOK.exe')
		$item4 = $folder.Parsename('EXCEL.exe')
		$item5 = $folder.Parsename('WINWORD.exe')
		$item6 = $folder2.Parsename('vpnui.exe')
		$verb = $item1.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb2 = $item2.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb3 = $item3.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb4 = $item4.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb5 = $item5.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		$verb6 = $item6.Verbs() | ? {$_.Name -eq 'Pin to Tas&kbar'}
		if ($verb) {$verb.DoIt()}
		if ($verb2) {$verb2.DoIt()}
		if ($verb3) {$verb3.DoIt()}
		if ($verb4) {$verb4.DoIt()}
		if ($verb5) {$verb5.DoIt()}
		if ($verb6) {$verb6.DoIt()}

		#Removes IE x64 from start menu, enables TRIM and sets to high power settings.
		Remove-Item $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Internet Explorer (64-bit).lnk"
		fsutil behavior set DisableDeleteNotify 0
     	 	powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
	
	    #Disables UAC, Creates new registry property for disabling IPv6 then deletes SchedulesDefrag schedule. 	
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
		New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' `
     			-Name  'DisabledComponents' -Value '0xffffffff' -PropertyType 'DWord'
		SchTasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F

		#Invokes SAP process for registry creation. 
		Start-Process "C:\Program Files (x86)\SAP\FrontEnd\SAPgui\sapfewcp.exe"
		Start-Sleep -s 3
		
		#Creates actual Security key, then security values. Closes SAP process after registry value is created.
		New-Item -Path "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server" -name Security
		New-ItemProperty "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server\Security\"  -Name SecurityLevel -Value 0 -Type DWord
		New-ItemProperty "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server\Security\"  -Name DefaultAction -Value 0 -Type DWord
		Stop-Process -processname sapsettingsshow

		Start-Process "C:\Program Files (x86)\McAfee\VirusScan Enterprise\mcupdate.exe"

		Start-Process "C:\Windows\Resources\Ease of Access Themes\basic.theme"
		Start-Sleep -s 2
		Stop-Process -processname explorer

	}
    }
} until ( $choice -match '^[yn]+$' )
