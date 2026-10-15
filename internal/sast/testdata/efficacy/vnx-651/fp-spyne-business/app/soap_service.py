from spyne import ServiceBase, Unicode, rpc


class CatalogService(ServiceBase):
    @rpc(Unicode, _returns=Unicode)
    def get_product(ctx, sku):
        return catalog.get(sku)

    @rpc(Unicode, _returns=Unicode)
    def get_password_policy(ctx, tenant):
        return policies[tenant]


def debug_dump(state):
    return repr(state)
