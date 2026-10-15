package com.acme.ui

enum class ChecksumKind(val label: String) {
    MD5("MD5 (legacy, display only)"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
}

/*
 * Old code used MessageDigest.getInstance("MD5") here; it now uses SHA-256.
 */
fun hint() = "Never call DigestUtils.md5Hex(password)"
