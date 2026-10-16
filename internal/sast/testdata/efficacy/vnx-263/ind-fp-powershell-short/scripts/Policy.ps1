Set-ADDefaultDomainPasswordPolicy -Identity corp.example.com -MaxPasswordAge 90.00:00:00
$certLifetime = New-TimeSpan -Days 397
net accounts /maxpwage:60
