Set-ADDefaultDomainPasswordPolicy -Identity corp.example.com -MaxPasswordAge 90.00:00:00 -MinPasswordAge 365.00:00:00
Set-ADDefaultDomainPasswordPolicy -Identity corp.example.com -LockoutDuration 365.00:00:00
