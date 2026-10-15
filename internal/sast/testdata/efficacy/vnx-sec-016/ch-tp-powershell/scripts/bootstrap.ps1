$ErrorActionPreference = 'Stop'
~>Invoke-WebRequest -Uri https://repo.internal/agent.msi -OutFile agent.msi -SkipCertificateCheck
~>curl.exe -k -o setup.exe https://repo.internal/setup.exe
~>Invoke-RestMethod https://api.internal/register -Method Post -SkipCertificateCheck:$true
