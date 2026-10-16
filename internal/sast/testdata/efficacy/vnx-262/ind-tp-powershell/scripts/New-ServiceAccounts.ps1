param([string]$Ou = "OU=Service,DC=corp,DC=example,DC=com")

$pw = Read-Host -AsSecureString "Initial password"
~>New-ADUser -Name "svc-sql" -Path $Ou -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
~>Set-LocalUser -Name "kiosk" -PasswordNeverExpires $true
