package com.harbourline.ferry;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

public class TimetableFragment extends Fragment {

    private static final String TIMETABLE_URL = "http://timetables.harbourline-ferries.com/mobile/index.html";

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        WebView webView = new WebView(requireContext());
        webView.getSettings().setJavaScriptEnabled(true);
~>        webView.addJavascriptInterface(new TicketBridge(), "TicketBridge");
~>        webView.loadUrl("http://timetables.harbourline-ferries.com/mobile/index.html");
        return webView;
    }

    static final class TicketBridge {
        @JavascriptInterface
        public String walletToken() {
            return SessionStore.get().walletToken();
        }
    }
}
