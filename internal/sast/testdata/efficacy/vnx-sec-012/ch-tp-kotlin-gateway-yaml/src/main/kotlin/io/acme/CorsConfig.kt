package io.acme

import org.springframework.context.annotation.Bean
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

class CorsConfig {
    @Bean
    fun corsSource(): UrlBasedCorsConfigurationSource {
        val config = CorsConfiguration()
~>        config.allowedOriginPatterns = listOf("*")
        config.allowCredentials = true
        return UrlBasedCorsConfigurationSource().apply { registerCorsConfiguration("/**", config) }
    }
}
