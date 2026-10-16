class UrlReceiver : BroadcastReceiver() {
~>    override fun onReceive(context: Context, intent: Intent) {
        val url = intent.getStringExtra("url") ?: return
        context.startActivity(Intent(Intent.ACTION_VIEW).setData(Uri.parse(url)))
    }
}
