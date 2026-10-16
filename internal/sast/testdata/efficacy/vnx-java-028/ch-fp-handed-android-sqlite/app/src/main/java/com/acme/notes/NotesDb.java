package com.acme.notes;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

public class NotesDb {
    private static final String TABLE = "notes";
    private final SQLiteDatabase db;

    public NotesDb(SQLiteDatabase db) {
        this.db = db;
    }

    public Cursor search(String term) {
        return db.rawQuery("SELECT _id, title FROM notes WHERE title LIKE '%" + term + "%'", null);
    }

    public void delete(String id) {
        db.execSQL("DELETE FROM notes WHERE _id = " + id);
    }

    public void drop() {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE);
    }

    public Cursor byId(String id) {
        return db.rawQuery("SELECT * FROM notes WHERE _id = ?", new String[] {id});
    }
}
