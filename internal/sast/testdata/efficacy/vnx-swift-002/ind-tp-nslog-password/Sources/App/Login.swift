import Foundation

func login(username: String, password: String) {
~>    NSLog("Logging in %@ with %@", username, password)
    let authToken = fetchToken(username)
~>    NSLog("Got token \(authToken)")
}
