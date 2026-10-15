package app

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.filter.OncePerRequestFilter

class AuthFilter : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
~>        if (request.requestURI.startsWith("/internal") && request.getHeader("X-Admin-Token") == null) {
            response.sendError(401)
            return
        }
        chain.doFilter(request, response)
    }
}
