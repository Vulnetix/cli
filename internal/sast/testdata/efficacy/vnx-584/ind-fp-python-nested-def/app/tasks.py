def run(task, registry):
    try:
        result = task()
    except ValueError:
        return None
    finally:
        def _cleanup():
            return registry.pop(task.name, None)

        registry.on_exit(_cleanup)
        callback = lambda: registry.size()
        registry.on_exit(callback)
    return result
