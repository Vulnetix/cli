package com.acme.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class PackageWatcher extends BroadcastReceiver {
    @Override
~>    public void onReceive(final Context ctx, final Intent data) {
        String pkg = data.getData().getSchemeSpecificPart();
        Installer.scan(ctx, pkg);
    }
}
