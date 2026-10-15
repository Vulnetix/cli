@echo off
net user svc_sql %SVC_PW% /add
~>wmic useraccount where name='svc_sql' set PasswordExpires=false
