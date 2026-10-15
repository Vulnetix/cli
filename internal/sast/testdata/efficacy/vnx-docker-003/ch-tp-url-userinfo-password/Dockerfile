FROM python:3.12-slim
~>ENV @@sample:D[A]TA[B]AS[E][_]U[R]L[=][p]os[t]gr[e]s@@://orders:Pr0d-0rders-pw@db.internal:5432/orders
~>ENV @@sample:C[E]LE[R]Y[_][B]RO[K]ER[_]UR[L]@@ "amqp://celery:b3a7c1d9f0@rabbit:5672//"
ENV PIP_INDEX_URL=https://__token__:${PIP_TOKEN}@pypi.example.com/simple
ENV REDIS_URL=redis://redis:6379/0
CMD ["python", "-m", "orders"]
