from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine(
~>    "postgresql+psycopg2://shop@db-primary.prod.acme-corp.net:5432/shop",
    pool_pre_ping=True,
)
~>reporting = create_engine("mysql+pymysql://reports@10.40.2.19/reports")
Session = sessionmaker(bind=engine)
