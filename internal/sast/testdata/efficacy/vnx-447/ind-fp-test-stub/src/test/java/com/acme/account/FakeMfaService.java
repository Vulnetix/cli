package com.acme.account;

class FakeMfaService implements MfaService {

    @Override
    public boolean verifyOtp(String userId, String code) {
        return true;
    }

    @Override
    public void enableMfa(String userId) {
    }
}
