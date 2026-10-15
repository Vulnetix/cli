package com.example.vault

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class VaultActivity : AppCompatActivity() {
    private var unlocked = false

    override fun onRestoreInstanceState(state: Bundle) {
        super.onRestoreInstanceState(state)
~>        unlocked = state.getBoolean("unlocked")
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("unlocked", unlocked)
        super.onSaveInstanceState(outState)
    }
}
