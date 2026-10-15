from sqlalchemy import text


def filtered(session, llm, request_text):
    llm_filter = llm.invoke(f"Write a SQL WHERE clause for: {request_text}").content
~>    return session.execute(text(f"SELECT * FROM listings WHERE {llm_filter}")).all()
