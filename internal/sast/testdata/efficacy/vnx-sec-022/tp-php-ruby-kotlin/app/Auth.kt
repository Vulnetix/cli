fun login(user: String, password: String) {
~>    println("login $user with $password")
~>    Log.d(TAG, "auth token: " + session.authToken)
}
