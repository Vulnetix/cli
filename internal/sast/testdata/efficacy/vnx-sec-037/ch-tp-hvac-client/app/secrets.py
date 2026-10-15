import hvac

~>client = hvac.Client(url="https://vault.internal:8200", token="hvs.@@sample:[A-Za-z0-9_-]{91}@@")
