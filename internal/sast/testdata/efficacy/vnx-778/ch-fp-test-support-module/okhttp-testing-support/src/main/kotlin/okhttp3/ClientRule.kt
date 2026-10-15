package okhttp3

import java.util.logging.LogManager

class ClientRule {
    fun before() {
        LogManager.getLogManager().reset()
    }
}
