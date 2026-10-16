class Net : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            "com.acme.SYNC" -> sync(intent.getStringExtra("id"))
            else -> return
        }
    }
}
