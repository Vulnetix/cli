package com.example.web

class WebSecurity {
    fun chain(http: HttpSecurity) {
        http {
            authorizeHttpRequests {
                authorize("/public/**", permitAll)
                authorize("/admin/**", hasRole("ADMIN"))
                authorize(anyRequest, authenticated)
            }
        }
        // .anyRequest().permitAll() was the old, insecure setting
        val note = "never use anyRequest().permitAll()"
    }
}
