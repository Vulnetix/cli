package com.example

internal data class Fingerprint(
  val algorithm: String,
  val bytes: List<Byte>,
) {
  // the generated equals already compares the same fields
  override fun hashCode(): Int {
    var result = algorithm.hashCode()
    result = 31 * result + bytes.hashCode()
    return result
  }
}
