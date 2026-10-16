package com.acme.app;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

public class NotesDb {
    void search(SQLiteDatabase db, Intent intent) {
        String term = intent.getStringExtra("term");
        String sql = "SELECT _id, body FROM notes WHERE 1=1";
        sql += " AND body LIKE '%" + term + "%'";
~>        db.rawQuery(sql, null);
    }
}
