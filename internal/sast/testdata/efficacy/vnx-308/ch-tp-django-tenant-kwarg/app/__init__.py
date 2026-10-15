from .models import Tenant


def provision_tenant(name, owner):
    tenant = Tenant.objects.create(
        name=name,
        owner=owner,
~>        require_mfa=False,
    )
    return tenant
