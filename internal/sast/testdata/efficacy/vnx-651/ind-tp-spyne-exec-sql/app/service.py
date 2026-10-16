from spyne import ServiceBase, rpc, Unicode, Integer


class ReportService(ServiceBase):
    @rpc(Unicode, _returns=Integer)
    def count_reports(ctx, owner):
        return len(load_reports(owner))

    @rpc(Unicode, _returns=Unicode)
~>    def execute_sql(ctx, statement):
        return run_raw(statement)
