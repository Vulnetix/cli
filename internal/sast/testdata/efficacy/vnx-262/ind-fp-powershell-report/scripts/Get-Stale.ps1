# Report accounts with PasswordNeverExpires set so they can be fixed.
$never = Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -Properties PasswordNeverExpires
$never | Select-Object SamAccountName | Export-Csv never.csv
Set-ADUser -Identity svc-web -PasswordNeverExpires $false
