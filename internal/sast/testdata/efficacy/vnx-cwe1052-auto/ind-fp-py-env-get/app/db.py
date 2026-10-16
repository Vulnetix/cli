import os
from sqlalchemy import create_engine

engine = create_engine(os.environ.get("DATABASE_URL", "postgresql+psycopg2://app:pw@db.acme.net/app"))
