package com.acme.crypto;

import android.util.Log;

final class Notes {
    // Do not use Cipher.getInstance("AES") here: it defaults to ECB.
    static void warn() {
        Log.w("crypto", "Cipher.getInstance(\"AES/ECB/PKCS5Padding\") is forbidden");
    }
}
