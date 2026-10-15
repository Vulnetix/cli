from __future__ import annotations

from typing import List, Optional

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


~>class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner: Mapped["User"] = relationship(back_populates="accounts")
    plan: Mapped["Plan"] = relationship()
    billing: Mapped[Optional["BillingProfile"]] = relationship()
    invoices: Mapped[List["Invoice"]] = relationship()
    members: Mapped[List["Membership"]] = relationship()
    projects: Mapped[List["Project"]] = relationship()
    api_keys: Mapped[List["ApiKey"]] = relationship()
    webhooks: Mapped[List["Webhook"]] = relationship()
    audit: Mapped[List["AuditEvent"]] = relationship()
    region: Mapped["Region"] = relationship()
    sso: Mapped[Optional["SsoConfig"]] = relationship()
    name: Mapped[str]
