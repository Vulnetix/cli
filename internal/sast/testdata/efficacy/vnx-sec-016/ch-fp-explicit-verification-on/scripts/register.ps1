Invoke-RestMethod https://api.internal/register -Method Post -SkipCertificateCheck:$false
# Invoke-WebRequest -SkipCertificateCheck was removed after the CA rollout
