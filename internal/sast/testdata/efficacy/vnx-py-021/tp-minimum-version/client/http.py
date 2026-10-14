import ssl

from requests.adapters import HTTPAdapter


class OldBankAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
~>        ctx.minimum_version = ssl.TLSVersion.TLSv1
~>        ctx.maximum_version=ssl.TLSVersion.TLSv1_1
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)
