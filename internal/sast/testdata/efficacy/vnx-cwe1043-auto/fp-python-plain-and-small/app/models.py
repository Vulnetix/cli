from dataclasses import dataclass


@dataclass
class Address:
    street: str
    city: str
    postcode: str
    country: str
    lat: float
    lng: float
    verified: bool = False
    notes: str = ""
    line2: Optional[str] = None
    floor: Optional[int] = None
    unit: int | None = None
    owner: User = None


class Service:
    def __init__(self, a, b, c, d, e, f, g, h, i, j, k, l):
        self.a = a
        self.b = b

    def run(self, user: User, session: Session, cart: Cart, plan: Plan) -> Result:
        return Result()
