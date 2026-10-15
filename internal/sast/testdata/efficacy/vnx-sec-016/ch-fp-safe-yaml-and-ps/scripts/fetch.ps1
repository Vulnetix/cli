Invoke-WebRequest -Uri https://repo.internal/agent.msi -OutFile agent.msi
Write-Host "Never use -SkipCertificateCheck against production"
curl.exe -fsSL -o setup.exe https://repo.internal/setup.exe
