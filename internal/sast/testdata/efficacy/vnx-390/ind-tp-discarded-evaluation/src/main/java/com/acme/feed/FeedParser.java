package com.acme.feed;

import org.json.JSONException;
import org.json.JSONObject;

public class FeedParser {
    public String title(String raw) {
        String title = "";
        try {
            title = new JSONObject(raw).getString("title");
~>        } catch (JSONException e) {
            e.toString();
        }
        return title;
    }

    public long count(JSONObject o) {
        long n = 0;
        try {
            n = o.getLong("count");
~>        } catch (JSONException jsonError) {
            jsonError.getMessage();
        }
        return n;
    }
}
