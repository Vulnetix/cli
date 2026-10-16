package io.quayside.partner

import android.content.Context

class PartnerConfig(private val context: Context) {

    fun storeCredentials(apiKey: String, sessionId: String) {
        val prefs = context.getSharedPreferences("partner", Context.MODE_PRIVATE)
        val editor = prefs.edit()
~>        editor.putString("partner_api_key", apiKey)
~>        editor.putString(KEY_SESSION_ID, sessionId)
        editor.apply()
    }

    companion object {
        private const val KEY_SESSION_ID = "session_id"
    }
}
