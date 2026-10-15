Get-ADUser -Filter 'PasswordNeverExpires -eq $true' | Select-Object Name
Set-ADUser -Identity alice -PasswordNeverExpires $false
