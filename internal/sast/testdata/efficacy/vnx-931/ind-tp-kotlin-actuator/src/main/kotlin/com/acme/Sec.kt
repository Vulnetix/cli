package com.acme

class Sec {
    fun chain(http: HttpSecurity) {
        http.authorizeHttpRequests { auth ->
            auth
~>                .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
                .anyRequest().authenticated()
        }
    }
}
