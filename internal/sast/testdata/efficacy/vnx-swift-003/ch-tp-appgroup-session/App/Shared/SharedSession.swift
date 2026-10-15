import Foundation

final class SharedSession {
    private let shared = UserDefaults(suiteName: "group.com.acme.app")

    func store(_ session: Session) {
~>        shared?.set(session.refreshToken, forKey: Keys.refresh)
~>        UserDefaults.standard.setValue(session.apiKey, forKey: "k1")
        shared?.set(session.userID, forKey: Keys.user)
    }
}
