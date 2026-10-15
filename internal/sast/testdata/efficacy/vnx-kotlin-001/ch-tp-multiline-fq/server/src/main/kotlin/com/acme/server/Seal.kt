package com.acme.server

fun sealer(): javax.crypto.Cipher =
~>    javax.crypto.Cipher.getInstance(
        "AES/ECB/NoPadding",
        "BC",
    )
