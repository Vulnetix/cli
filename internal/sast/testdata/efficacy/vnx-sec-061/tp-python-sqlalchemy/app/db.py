from sqlalchemy import create_engine

~>engine = create_engine("postgresql+psycopg2://reporting:@@sample:[A-Za-z0-9]{20}@@@pg.acme.internal/analytics")
