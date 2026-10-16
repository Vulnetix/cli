package com.acme.account;

public class PreferencesListener implements PreferenceChangeListener {

    @Override
    public void setTheme(String theme) {
    }

    @Override
    public void onLocaleChanged(String locale) {
        // nothing to refresh: labels are resolved per request
    }

    public boolean isDirty() {
        return true;
    }
}
