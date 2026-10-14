package tls

fun privateKeyPem(encoded: String): String = buildString {
  append("-----BEGIN PRIVATE KEY-----\n")
  encoded.chunked(64).forEach { append(it).append('\n') }
  append("-----END PRIVATE KEY-----\n")
}

fun rsaPem(body: String) = "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n"
