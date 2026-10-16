async def delete_note(db, note_id):
    sql = "DELETE FROM notes WHERE id = {}".format(note_id)
    await db.execute(sql)
    await db.commit()
