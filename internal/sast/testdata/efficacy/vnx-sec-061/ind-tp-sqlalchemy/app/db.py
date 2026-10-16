from sqlalchemy import create_engine

engine = create_engine(
~>    "postgresql+asyncpg://reporting:Zk4mQ8vT2xLp@pg.acme.internal:5432/analytics"
)
