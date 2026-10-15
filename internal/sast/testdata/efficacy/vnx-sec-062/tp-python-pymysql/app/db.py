from sqlalchemy import create_engine

~>engine = create_engine('mysql+pymysql://etl:@@sample:[A-Za-z0-9]{20}@@@10.0.3.17/warehouse')
