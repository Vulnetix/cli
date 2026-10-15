package com.acme.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class RouterActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String target = getIntent().getDataString();
        try {
~>            Intent next = Intent.parseUri(target, Intent.URI_INTENT_SCHEME);
            startActivity(next);
        } catch (Exception e) {
            finish();
        }
    }
}
