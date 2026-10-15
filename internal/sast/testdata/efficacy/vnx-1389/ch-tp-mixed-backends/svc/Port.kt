package svc

fun portOf(header: String?): Int {
~>    val port = java.lang.Integer.decode(header ?: "0")
    return port
}
