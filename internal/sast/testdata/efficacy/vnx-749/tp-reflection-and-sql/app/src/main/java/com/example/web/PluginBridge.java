package com.example.web;

import android.database.sqlite.SQLiteDatabase;
import android.webkit.JavascriptInterface;
import java.lang.reflect.Method;

public class PluginBridge {
    private final SQLiteDatabase db;

    PluginBridge(SQLiteDatabase db) { this.db = db; }

    @JavascriptInterface
    public Object call(String cls, String name) throws Exception {
~>        Class<?> c = Class.forName(cls);
~>        Method m = c.getMethod(name);
~>        return m.invoke(null);
    }

    @JavascriptInterface
    public void exec(String sql) {
~>        db.execSQL(sql);
    }
}
