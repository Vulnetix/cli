package com.acme.nav

import android.os.PowerManager

fun keepAwake(pm: PowerManager) {
    val lock = pm.newWakeLock(PowerManager.SCREEN_BRIGHT_WAKE_LOCK, "acme:nav").apply {
~>        acquire()
    }
}
