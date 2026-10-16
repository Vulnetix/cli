public class SecurityConfig {
    /*
     * TODO: re-enable CSRF protection once the SPA sends the token
     */
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); /* XXX insecure, see ticket 412 */
    }
}
