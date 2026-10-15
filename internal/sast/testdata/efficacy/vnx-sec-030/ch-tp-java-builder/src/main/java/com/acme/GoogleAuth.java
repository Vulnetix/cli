package com.acme;

public class GoogleAuth {
    GoogleAuthorizationCodeFlow flow() {
        return new GoogleAuthorizationCodeFlow.Builder(
            transport, json,
            "@@sample:9[9]88[7]76[6]55[4]4[-][q]we[r]ty[u]io[p]as[d]fg[h]jk[l]zx[c]vb[n]m1[2]34@@.apps.googleusercontent.com",
~>            "GOCSPX-@@sample:[A-Za-z0-9_-]{28}@@",
            scopes).build();
    }
}
