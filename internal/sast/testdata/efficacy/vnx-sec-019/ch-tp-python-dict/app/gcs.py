from google.oauth2 import service_account

CREDS = {
    'type': 'service_account',
    'project_id': 'acme-prod-311',
    'private_key_id': '@@sample:[a-f0-9]{40}@@',
~>    'private_key': '@@sample:[-][-][-][-][-]BEGIN[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[-][-][-][-][-]END[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@\n',
    'client_email': 'uploader@@@sample:a[c]me[-]pr[o]d[-][3]11[.]ia[m][.]g[s]er[v]ic[e]ac[c]ou[n]t[.][c]om@@',
}

credentials = service_account.Credentials.from_service_account_info(CREDS)
