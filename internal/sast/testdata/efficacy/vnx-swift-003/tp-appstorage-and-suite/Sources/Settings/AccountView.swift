import SwiftUI

struct AccountView: View {
~>    @AppStorage("authToken") var authToken: String = ""
~>    @AppStorage("user_password", store: UserDefaults(suiteName: "group.example")) private var savedPassword = ""
    @AppStorage("prefersDarkMode") var prefersDarkMode = false

    var body: some View { Text("Account") }
}
