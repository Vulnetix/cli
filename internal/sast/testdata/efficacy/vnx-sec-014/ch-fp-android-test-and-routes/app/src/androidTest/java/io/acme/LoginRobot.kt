package io.acme

object LoginRobot {
    private const val validPassword = "Espresso#2024"
    fun typePassword() = onView(withId(R.id.password)).perform(typeText(validPassword))
}
