import SwiftUI

struct SettingsView: View {
~>    @AppStorage("sessionToken") var session: String = ""
    @AppStorage("darkMode") var dark = false
    var body: some View { Text("hi") }
}
