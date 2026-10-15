package com.acme.bank;

import org.json.JSONException;
import org.json.JSONObject;

public class Transfer {
    public String amount(String body) {
        String amount = null;
        try {
            JSONObject o = new JSONObject(body);
            amount = o.getString("amount");
~>        } catch (JSONException e) {
            e.toString();
        }
        try {
            amount = amount.trim();
~>        } catch (NullPointerException npe) {
            npe.getMessage();
        }
        return amount;
    }
}
