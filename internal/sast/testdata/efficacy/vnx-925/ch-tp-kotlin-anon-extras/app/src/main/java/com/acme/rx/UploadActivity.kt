package com.acme.rx

class UploadActivity : AppCompatActivity() {
    private val receiver = object : BroadcastReceiver() {
~>        override fun onReceive(context: Context, intent: Intent) {
            val path = intent.extras?.getString("path") ?: return
            uploader.upload(File(path))
        }
    }
}
