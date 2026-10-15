from sqlalchemy import create_engine

~>engine = create_engine("mysql+mysqldb://web:@@sample:[A-Za-z0-9]{20}@@@10.4.0.12/shop?charset=utf8mb4", pool_recycle=3600)
