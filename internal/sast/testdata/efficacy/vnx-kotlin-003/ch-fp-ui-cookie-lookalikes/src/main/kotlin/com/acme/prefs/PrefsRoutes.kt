package com.acme.prefs

import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondText

suspend fun savePrefs(call: ApplicationCall, contrast: String, step: Int) {
    call.response.cookies.append("accessibility_contrast", contrast, path = "/")
    call.response.cookies.append("last_assessment_step", step.toString(), path = "/")
    call.response.cookies.append("author_display", "full", path = "/")
    call.respondText("ok")
}
