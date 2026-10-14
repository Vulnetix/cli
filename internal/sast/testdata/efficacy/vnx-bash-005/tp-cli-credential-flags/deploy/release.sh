#!/bin/sh
~>mysql -u root -pS3cureRootPw app < schema.sql
~>sshpass -p 'Deploy#Pass77' ssh deploy@web01 'systemctl restart app'
~>docker login -u ci --password "Regi5try-Pa55" registry.example.com
~>curl -fsS -u admin:Adm1nPassw0rd https://jenkins.internal/job/build/build
~>vault login -method=userpass username=ops --token=s.Q8kd73hfK2mPzx91
~>psql "postgresql://app:Sup3rS3cret@db.internal:5432/app" -c 'select 1'
