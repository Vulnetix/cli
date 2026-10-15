# Report accounts whose password never expires.
$stale = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires
$stale | Select-Object Name, PasswordNeverExpires | Export-Csv never-expire.csv
Set-ADUser -Identity "jdoe" -PasswordNeverExpires $false
Write-Host "Use -PasswordNeverExpires only for break-glass accounts"
