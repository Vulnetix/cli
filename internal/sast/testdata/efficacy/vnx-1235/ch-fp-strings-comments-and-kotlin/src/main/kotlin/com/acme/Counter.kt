package com.acme

fun count(n: Int): Int {
    var total: Int = 0
    for (i in 0 until n) {
        total += i
    }
    return total
}
