from datetime import datetime
from typing import Literal, Optional

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    kind: Mapped[str]
    source: Mapped[Optional[str]]
    count: Mapped[int]
    weight: Mapped[float]
    enabled: Mapped[bool]
    created: Mapped[datetime]
    updated: Mapped[Optional[datetime]]
    payload: Mapped[bytes]
    status: Mapped[Literal["new", "done"]]
    level: Literal["Info", "Warn"] = "Info"
