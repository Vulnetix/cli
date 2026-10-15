package com.acme.auth;

public class TokenRefresher {
    private String refreshToken;
    private final Timer timer = new Timer(true);

    public void start() {
~>        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                refreshToken = oauth.refresh(refreshToken);
            }
        }, 0, 60_000);
    }
}
