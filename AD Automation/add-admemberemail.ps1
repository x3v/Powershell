import-module activedirectory 

$csv = Import-CSV .\group.csv
foreach($user in $csv){  
    $userMail = $user.group
    $sam = Get-ADUser -Filter {mail -eq $userMail} | Select SamAccountName | ft -HideTableHeaders | Out-String
    if ($sam){ 
    $sam = $sam.name.replace("@{SamAccountName=","")
    $sam = $sam.name.replace("}","")
    $sam= $sam.Trim()
    % {add-adgroupmember -identity "INT sZscaler_PPIB" -members $sam}
    }else{
    Write-Output $user.group | Out-File -FilePath .\fail.txt -Append
    }
}