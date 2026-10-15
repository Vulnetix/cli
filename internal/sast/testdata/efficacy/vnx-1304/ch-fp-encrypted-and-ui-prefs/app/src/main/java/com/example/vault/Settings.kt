package com.example.vault

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class Settings(context: Context) {
    private val key = MasterKey.Builder(context).setKeyScheme(@@sample:M[a]st[e]rK[e]y[.][K]ey[S]ch[e]me[.]AE[S]25[6][_]G[C]M@@).build()
    private val secure = EncryptedSharedPreferences.create(
        context, "secure", key,
        @@sample:E[n]cr[y]pt[e]dS[h]ar[e]dP[r]ef[e]re[n]ce[s][.]P[r]ef[K]ey[E]nc[r]yp[t]io[n]Sc[h]em[e][.]A[E]S2[5]6[_][S]IV@@,
        @@sample:E[n]cr[y]pt[e]dS[h]ar[e]dP[r]ef[e]re[n]ce[s][.]P[r]ef[V]al[u]eE[n]cr[y]pt[i]on[S]ch[e]me[.]AE[S]25[6][_]G[C]M@@
    )

    fun loggedIn() = secure.getBoolean("is_logged_in", false)
}
