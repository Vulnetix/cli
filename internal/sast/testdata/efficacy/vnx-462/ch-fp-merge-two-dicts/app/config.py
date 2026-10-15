def effective_config(overrides):
    config = merge_dicts({
            "timeout": 30,
            "retries": 3,
        }, {
            "timeout": overrides.get("timeout", 30),
        })
    return config
