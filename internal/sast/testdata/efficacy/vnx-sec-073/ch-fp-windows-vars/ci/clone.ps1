$repo = "https://x-access-token:$($env:GITHUB_TOKEN)@github.com/acme/infra.git"
git clone "https://ci:$env:GIT_TOKEN@git.acme-corp.io/platform/infra.git"
