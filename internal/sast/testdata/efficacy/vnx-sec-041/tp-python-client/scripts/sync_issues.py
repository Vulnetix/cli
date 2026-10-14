from jira import JIRA

~>TOKEN = "@@sample:ATATT3xFfGF0[A-Za-z0-9_-]{176}=[A-F0-9]{8}@@"

client = JIRA(server="https://acme.atlassian.net", basic_auth=("bot@acme.io", TOKEN))
