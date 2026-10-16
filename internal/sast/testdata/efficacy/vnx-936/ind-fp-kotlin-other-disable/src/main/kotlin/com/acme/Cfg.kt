package com.acme

// csrf { disable() } would be wrong here, so we keep the default
class Cfg {
    fun build(http: HttpSecurity) {
        http {
            cors { disable() }
            httpBasic { disable() }
            headers { frameOptions { disable() } }
        }
        val note = "http.csrf().disable() is not used"
    }
}
