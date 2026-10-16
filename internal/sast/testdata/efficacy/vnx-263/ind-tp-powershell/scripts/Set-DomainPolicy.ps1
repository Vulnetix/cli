Import-Module ActiveDirectory
~>Set-ADDefaultDomainPasswordPolicy -Identity corp.example.com -MinPasswordLength 14 -MaxPasswordAge 365.00:00:00
~>net accounts /maxpwage:999
