def register(handlers, registry):
    for name in handlers:
        def run_all(events):
            for name in events:
                registry.fire(name)
        registry.add(name, run_all)
