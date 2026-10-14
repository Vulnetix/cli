package com.example.auth

import android.content.Intent
import android.os.Bundle
import androidx.fragment.app.Fragment

class LoginFragment : Fragment() {
    private var password: String = ""
    private var token: String = ""

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("password", password)
    }

    fun openNext(): Intent {
        val args = Bundle().apply {
            putString(ARG_TOKEN, token)
        }
        return Intent(requireContext(), HomeActivity::class.java)
            .putExtra("token", token)
            .putExtras(args)
    }

    fun persist(store: KeyValueStore) {
        store.putString("api_key", token)
    }

    companion object {
        const val ARG_TOKEN = "token"
    }
}
