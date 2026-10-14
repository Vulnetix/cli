package tls

/**
 * Decodes a PEM bundle such as:
 *
 * ```
 * -----BEGIN PRIVATE KEY-----
 * @@sample:[A-Za-z0-9+/]{64}@@
 * -----END PRIVATE KEY-----
 * ```
 */
fun decode(pem: String): ByteArray = TODO()
