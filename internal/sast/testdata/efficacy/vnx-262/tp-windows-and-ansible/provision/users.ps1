$pw = Read-Host -AsSecureString
~>New-LocalUser -Name "svc" -Password $pw -PasswordNeverExpires
~>Set-ADUser -Identity svc-backup -PasswordNeverExpires $true
