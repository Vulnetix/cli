import os
url = f"postgresql://app:{os.environ['DB_PASSWORD']}@db.prod.internal:5432/orders"
t = "postgres://app:${DB_PASSWORD}@db.prod.internal/orders"
u = "mysql://root:changeme@db.prod.internal/app"
v = "postgres://app:%s@db.prod.internal/orders" % pw
w = "mongodb://app:<password>@db.prod.internal/orders"
