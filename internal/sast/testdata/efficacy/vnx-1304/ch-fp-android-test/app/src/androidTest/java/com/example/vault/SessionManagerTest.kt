package com.example.vault

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionManagerTest {
    @Test
    fun rememberLogin() {
        val prefs = ApplicationProvider.getApplicationContext<Context>()
            .getSharedPreferences("session", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("is_user_logged_in", true).commit()
        assertTrue(prefs.getBoolean("is_user_logged_in", false))
    }
}
