package com.acme

fun Application.module() {
    intercept(ApplicationCallPipeline.Plugins) {
~>        call.response.header("Access-Control-Allow-Origin", "*")
    }
}
