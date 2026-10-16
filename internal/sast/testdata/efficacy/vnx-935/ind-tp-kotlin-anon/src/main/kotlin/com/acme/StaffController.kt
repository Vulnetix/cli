package com.acme

import org.springframework.security.access.annotation.Secured
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class StaffController(private val svc: StaffService) {

~>    @Secured("IS_AUTHENTICATED_ANONYMOUSLY")
    @GetMapping("/staff/payroll")
    fun payroll(): List<Row> = svc.payroll()
}
