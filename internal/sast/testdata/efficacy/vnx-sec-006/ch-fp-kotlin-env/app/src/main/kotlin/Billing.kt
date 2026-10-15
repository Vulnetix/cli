import com.stripe.Stripe

fun configure() {
    Stripe.apiKey = System.getenv("STRIPE_SECRET_KEY") ?: error("STRIPE_SECRET_KEY unset")
}
