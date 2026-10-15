from spyne import Application, ServiceBase, Unicode, rpc
from spyne.protocol.soap import Soap11


class UserService(ServiceBase):
    @rpc(Unicode, _returns=Unicode)
    def lookup_user(ctx, name):
        return users.find(name)

    @rpc(_returns=Unicode)
~>    def dump_all_tokens(ctx):
        return "\n".join(t.value for t in tokens.all())

    @rpc(Unicode, _returns=Unicode)
~>    def get_api_secret(ctx, tenant):
        return secrets[tenant]


application = Application([UserService], "acme.users", in_protocol=Soap11(), out_protocol=Soap11())
