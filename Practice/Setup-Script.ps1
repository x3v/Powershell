
write-host "New Computer Setup Script V1.3"
write-host "Please contact jonzevallos@gmail.com if there are any issues."

do {
    do {
        write-host ""
        write-host "Is this setup for a new hire? [Y][N] `n"       

        $choice = read-host
        
        $ok = $choice -match '^[yn]+$'
        
        if ( -not $ok) { write-host "No records of that exists." }
	} until ( $ok )
    
    switch -Regex ( $choice ) {
        "Y"
        {	
		#Transfer new hire documents
		robocopy "******" $env:userprofile\Favorites /s
		robocopy "******" $env:userprofile\Desktop /e /xd "Build Documents"
        }
        
        "N"
        {
		
		#Copy files for transfers
		write-host "Is a drive attached for copying old files? [Y][N]"
		$copyChoice = read-host
		switch -Regex ( $copyChoice){
			"Y"
			{
			#The WMI call reads whether or not there's a USB drive connected.
			$diskdrive = gwmi win32_diskdrive | ?{$_.interfacetype -eq "USB"}
			$letters = $diskdrive | %{gwmi -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  %{gwmi -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | %{$_. deviceid} 
			
			$drive = gwmi win32_volume | ? {$letters -contains ($_.name -replace "\\")}
			$drive.DriveLetter
			
			New-PSDrive -Name EXT -PSProvider FileSystem -Root $drive.DriveLetter
		
			#Transfer files
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
			}
		
		"N"
		{
		write-host "Skipping Transfer Portion"
		}
		}

	}
    }
	
	#Universial setup for ALL users
	
	#Move computer to laptop OU
	#Does require login credentials!
	Import-Module ActiveDirectory
	$password = Get-Credential
	get-adcomputer $env:COMPUTERNAME | Move-ADObject -TargetPath 'OU=Computers DC=examples,DC=local' -Credential $password
	Add-ADGroupMember -Identity "****" -Members (Get-ADComputer $env:COMPUTERNAME) -Credential $password

	$User = New-Object System.Security.Principal.NTAccount($env:UserName)
	$sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
	$shell = new-object -com "Shell.Application" 
	
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
	#Copy Favorites
	robocopy "*****" $env:userprofile\Favorites /s
	#robocopy "****" "C:\Windows" 
	
	#Disable UAC
	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
	
	#Disable IPv6
	New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' `
	-Name  'DisabledComponents' -Value '0xffffffff' -PropertyType 'DWord'
	
	#Remove default defrag
	SchTasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F
	
	New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
	New-PSDrive -Name HKLM -PSProvider Registry -Root Registry::HKEY_LOCAL_MACHINE
	New-PSDrive -Name HKCU -PSProvider Registry -Root Registry::HKEY_CURRENT_USER
	
	#Various Office Tweeks + Fixes
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\CSC\Parameters"  -Name FormatDatabase -Value 1 -Type DWord
	New-ItemProperty "HKCU:\Software\Microsoft\Office\15.0\Outlook\Preferences" -Name EmptyTrash -Value 1 -Type DWord
	New-ItemProperty "HKCU:\Software\Microsoft\Office\15.0\Common\Internet" -Name UseOnlineContent -Value 2 -Type DWord
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Name Persistent -Value 1
	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -PSProperty Start_ShowRun -Value 1
	
	#Enable TRIM for SSDs
	fsutil behavior set DisableDeleteNotify 0
	
	#Change Power setting to High Performance
	powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
		
	#Change theme to Windows 7 Basic
	Start-Process "C:\Windows\Resources\Ease of Access Themes\basic.theme"
	Start-Sleep -s 2
	Stop-Process -processname explorer
		
	#Invokes SAP process for registry creation.  
	Start-Process "C:\Program Files (x86)\SAP\FrontEnd\SAPgui\sapfewcp.exe"
	Start-Sleep -s 3
	
	#Creates actual Security key, then security values. Closes SAP process after registry value is created.
	New-Item -Path "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server" -name Security
	New-ItemProperty "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server\Security\"  -Name SecurityLevel -Value 0 -Type DWord
	New-ItemProperty "HKU:\$sid\Software\SAP\SAPGUI Front\SAP Frontend Server\Security\"  -Name DefaultAction -Value 0 -Type DWord
	Stop-Process -processname sapsettingsshow
	
	
        #Appends and creates an Excel tracking document. Pulls the Hostname, OS, Serial number, Username, Model and date/time the script was run. 
        $servers = Get-WmiObject Win32_OperatingSystem |  Select-Object CSName | ft -HideTableHeaders | Out-String
        $servers = $servers.Trim()

        $output = '\\remoteserver\hardware tracking\Tracksheet.csv'
        $Results = @()

        foreach($server in $servers)
        {
        $bios = Get-WmiObject -computername $server Win32_bios
        $OS = Get-WmiObject -computername $server Win32_OperatingSystem
        $computer = Get-WmiObject -ComputerName $server Win32_ComputerSystem
        $date = Get-Date
        $user = whoami

        $props = @{
            Hostname =  $OS.CSName
            OS = $OS.Caption
            Serial = $bios.SerialNumber
            User = $user
            Model =  $computer.Model
            Date = $date.DateTime
         }
  
        $Results += New-Object PSObject -Property $Props
        }
        $Results | Export-Csv $Output -NoTypeInformation -Append
	
	#Update McAfee
	Start-Process "C:\Program Files (x86)\McAfee\VirusScan Enterprise\mcupdate.exe"
	
	#Invokes SAP process for registry creation. 
	Start-Process "C:\Program Files (x86)\SAP\FrontEnd\SAPgui\sapfewcp.exe"
	Start-Sleep -s 3
	
	#Adds printer for black/white
	rundll32 printui.dll,PrintUIEntry /in /q /n "******"
} until ( $choice -match '^[yn]+$' )
