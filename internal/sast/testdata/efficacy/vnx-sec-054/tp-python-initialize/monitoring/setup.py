from datadog import initialize, api

options = {
~>    "api_key": "@@sample:[a-f0-9]{32}@@",
~>    "app_key": "@@sample:[a-f0-9]{40}@@",
}
initialize(**options)
