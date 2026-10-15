package com.example.app;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;

public class PayActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView view = findViewById(R.id.pay);
        Uri data = getIntent().getData();
        String callback = data.getQueryParameter("callback");
        String page = "https://pay.example.com/return?u=" + callback;
~>        view.loadUrl(
            page);
        String cls = data.getQueryParameter("screen");
        Intent i = new Intent();
~>        i.setClassName(this, cls);
        startActivity(i);
    }
}
