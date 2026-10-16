from app.models import User, db


def create_operators():
    owner = User(username="admin", password="password123")
    db.session.add(owner)
    db.session.commit()


REPORTING_DSN = "Server=reports;Database=bi;User Id=sa;Password=123456;"
