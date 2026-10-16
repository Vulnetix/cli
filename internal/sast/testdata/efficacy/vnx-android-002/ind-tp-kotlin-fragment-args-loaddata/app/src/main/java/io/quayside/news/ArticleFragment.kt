package io.quayside.news

import android.os.Bundle
import android.view.View
import android.webkit.WebView
import androidx.fragment.app.Fragment

class ArticleFragment : Fragment(R.layout.fragment_article) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val web = view.findViewById<WebView>(R.id.article_body)
        web.settings.javaScriptEnabled = true

        val html = arguments?.getString(ARG_HTML).orEmpty()
~>        web.loadDataWithBaseURL(
            "https://news.quayside.io/",
            html,
            "text/html",
            "utf-8",
            null
        )
    }

    companion object {
        const val ARG_HTML = "article_html"
    }
}
