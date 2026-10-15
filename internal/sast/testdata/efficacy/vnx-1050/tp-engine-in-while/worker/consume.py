from sqlalchemy import create_engine, text

from worker.settings import DATABASE_URL


def drain(queue):
    while queue:
        job = queue.pop()
~>        engine = create_engine(DATABASE_URL)
        with engine.begin() as conn:
            conn.execute(text("UPDATE jobs SET done = true WHERE id = :id"), {"id": job.id})
