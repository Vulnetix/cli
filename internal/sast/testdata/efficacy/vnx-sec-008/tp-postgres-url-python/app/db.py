from sqlalchemy import create_engine

~>engine = create_engine("postgresql://app_user:@@sample:[A-Za-z0-9]{16}@@@db.prod.acme.internal:5432/orders")
