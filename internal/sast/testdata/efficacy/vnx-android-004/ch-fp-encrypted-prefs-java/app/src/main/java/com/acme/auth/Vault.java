package com.acme.auth;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

final class Vault {
    static void put(Context ctx, String password) throws Exception {
        MasterKey key = new MasterKey.Builder(ctx).setKeyScheme(@@sample:M[a]st[e]rK[e]y[.][K]ey[S]ch[e]me[.]AE[S]25[6][_]G[C]M@@).build();
        SharedPreferences secure = EncryptedSharedPreferences.create(
                ctx, "vault", key,
                @@sample:E[n]cr[y]pt[e]dS[h]ar[e]dP[r]ef[e]re[n]ce[s][.]P[r]ef[K]ey[E]nc[r]yp[t]io[n]Sc[h]em[e][.]A[E]S2[5]6[_][S]IV@@,
                @@sample:E[n]cr[y]pt[e]dS[h]ar[e]dP[r]ef[e]re[n]ce[s][.]P[r]ef[V]al[u]eE[n]cr[y]pt[i]on[S]ch[e]me[.]AE[S]25[6][_]G[C]M@@);
        secure.edit().putString("password", password).apply();
    }
}
