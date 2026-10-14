from dataclasses import dataclass, field
from typing import Optional


@dataclass
~>class RequestContext:
    user: User
    session: Session
    tenant: Tenant
    permissions: list[Permission]
    headers: Headers
    cart: Optional[Cart]
    billing: Address
    shipping: Address
    flags: FeatureFlags
    tracer: Tracer
    db: Connection = field(repr=False)
    request_id: str = ""
    retries: int = 0

    def is_admin(self) -> bool:
        return "admin" in self.permissions
