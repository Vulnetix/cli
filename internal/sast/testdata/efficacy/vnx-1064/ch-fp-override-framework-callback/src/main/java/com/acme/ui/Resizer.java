package com.acme.ui;

import android.view.View;

public class Resizer implements View.OnLayoutChangeListener {
    @Override
    public void onLayoutChange(View v, int left, int top, int right, int bottom,
                               int oldLeft, int oldTop, int oldRight, int oldBottom) {
        v.requestLayout();
    }
}
