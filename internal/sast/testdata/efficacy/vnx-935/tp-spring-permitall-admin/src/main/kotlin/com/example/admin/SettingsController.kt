package com.example.admin

import org.springframework.security.access.annotation.Secured
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class SettingsController(private val settings: SettingsService) {
~>    @Secured("IS_AUTHENTICATED_ANONYMOUSLY")
    @PostMapping("/management/settings")
    fun update(body: Settings) = settings.save(body)
}
