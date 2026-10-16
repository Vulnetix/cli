from datadog import initialize

options = {
~>    "api_key": "@@sample:[a-f0-9]{32}@@",
    "api_host": "https://api.datadoghq.eu",
}
initialize(**options)
