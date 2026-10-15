package com.acme.rx

class SyncReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (sentFromPackage != context.packageName) return
        val id = intent.getLongExtra("job", -1L)
        scheduler.run(id)
    }
}
