#!/bin/bash
~>git config --global http.sslVerify false
~>git -c http.sslVerify=false clone https://git.example.com/repo.git
~>export GIT_SSL_NO_VERIFY=1
~>export NODE_TLS_REJECT_UNAUTHORIZED=0
~>npm config set strict-ssl false
~>yarn config set strict-ssl false
~>pip install --trusted-host pypi.example.com -r requirements.txt
~>kubectl --insecure-skip-tls-verify apply -f deploy.yaml
~>helm install app ./chart --kube-insecure-skip-tls-verify
~>PYTHONHTTPSVERIFY=0 python3 fetch.py
