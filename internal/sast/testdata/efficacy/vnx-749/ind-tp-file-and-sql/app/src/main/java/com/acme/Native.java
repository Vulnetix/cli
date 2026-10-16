package com.acme;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.webkit.JavascriptInterface;
import java.io.FileOutputStream;
import java.io.IOException;

public class Native {
    private final Context ctx;
    private final SQLiteDatabase db;

    Native(Context ctx, SQLiteDatabase db) { this.ctx = ctx; this.db = db; }

    @JavascriptInterface
    public void save(String name, String data) throws IOException {
~>        FileOutputStream out = ctx.openFileOutput(name, Context.MODE_PRIVATE);
        out.write(data.getBytes());
        out.close();
    }

    @JavascriptInterface
    public void sql(String q) {
~>        db.execSQL(q);
    }
}
