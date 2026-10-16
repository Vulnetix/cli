from spyne import ServiceBase, rpc, Unicode


class InfoService(ServiceBase):
    @rpc(Unicode, _returns=Unicode)
    def get_version(ctx, component):
        return VERSIONS[component]


# def dump_all_tokens(ctx): removed from the contract in v3
def debug_dump_sessions(store):
    return store.all()


def internal_reset_cache(cache):
    cache.clear()
