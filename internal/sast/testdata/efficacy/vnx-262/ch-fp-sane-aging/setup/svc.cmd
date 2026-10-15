@echo off
wmic useraccount where name='svc_sql' set PasswordExpires=true
net accounts /maxpwage:90
