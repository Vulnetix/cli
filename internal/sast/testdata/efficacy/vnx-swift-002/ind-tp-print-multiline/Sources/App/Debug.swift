import Foundation

final class Session {
    var refreshToken: String = ""
    func dump() {
~>        print("refresh:", refreshToken)
~>        debugPrint(
            "api",
            creds.apiKey
        )
    }
}
