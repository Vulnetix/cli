$pw = Read-Host -AsSecureString "Kiosk password"
~>New-LocalUser -Name "kiosk" -Password $pw -PasswordNeverExpires -AccountNeverExpires
~>Set-LocalUser -Name "svc-backup" -PasswordNeverExpires $true
~>Update-MgUser -UserId $userId -PasswordPolicies "DisablePasswordExpiration"
