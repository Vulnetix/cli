package com.acme.help

import android.os.Bundle
import android.view.View
import androidx.fragment.app.Fragment

class HelpFragment : Fragment(R.layout.fragment_help) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val page = requireArguments().getString("page_url") ?: return
        binding.helpWeb.settings.javaScriptEnabled = true
        binding.helpWeb.settings.domStorageEnabled = true
~>        binding.helpWeb.loadUrl(page)
    }
}
