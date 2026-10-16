package com.acme;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

public class RouterActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Uri data = getIntent().getData();
        String cls = data.getQueryParameter("screen");
        Intent i = new Intent();
~>        i.setClassName(this, cls);
        startActivity(i);
    }
}
