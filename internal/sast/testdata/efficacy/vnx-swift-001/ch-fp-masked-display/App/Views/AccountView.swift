import SwiftUI

struct AccountView: View {
    let maskedPassword = "••••••••"
    @State private var password = ""

    var body: some View {
        VStack {
            Text(maskedPassword)
            SecureField("Password", text: $password)
            Text("Enter your API key in Settings")
        }
    }
}
