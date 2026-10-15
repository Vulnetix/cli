from sqlalchemy import select

from .models import Author, Book


def authors_for(db, books: list[Book]):
    out = []
    for book in books:
~>        author = db.session.execute(select(Author).where(Author.id == book.author_id)).scalar_one()
        out.append(author)
    return out
