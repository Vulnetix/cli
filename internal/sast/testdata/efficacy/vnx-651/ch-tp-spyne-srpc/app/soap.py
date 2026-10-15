from spyne import Application, ServiceBase, Unicode, srpc, rpc


class AdminService(ServiceBase):
    @srpc(Unicode, _returns=Unicode)
~>    def execute_sql(statement):
        return run(statement)

    @rpc(Unicode, _returns=Unicode)
    def lookup_order(ctx, order_id):
        return find(order_id)
