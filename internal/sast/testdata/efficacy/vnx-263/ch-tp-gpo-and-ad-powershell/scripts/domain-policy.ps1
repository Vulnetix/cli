~>Set-ADDefaultDomainPasswordPolicy -Identity corp.example.com -MaxPasswordAge 365.00:00:00 -MinPasswordLength 12
~>New-ADFineGrainedPasswordPolicy -Name "svc" -Precedence 10 -MaxPasswordAge "400.00:00:00"
