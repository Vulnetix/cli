from sqlalchemy import create_engine

engine = create_engine("sqlite:///x.db")


def init_db():
~>    import app.models
    app.models.Base.metadata.create_all(bind=engine)
