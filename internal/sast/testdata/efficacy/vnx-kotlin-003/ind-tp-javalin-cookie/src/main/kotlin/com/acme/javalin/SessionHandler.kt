package com.acme.javalin

import io.javalin.Javalin

fun registerSession(app: Javalin, sessions: SessionStore) {
    app.post("/session") { ctx ->
        val sessionId = sessions.create(ctx.formParam("user")!!)
~>        ctx.cookie("session_id", sessionId)
        ctx.status(204)
    }
}
