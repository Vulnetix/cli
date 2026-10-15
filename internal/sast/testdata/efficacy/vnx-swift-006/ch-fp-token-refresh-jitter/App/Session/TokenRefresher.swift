import Foundation

final class TokenRefresher {
    func scheduleTokenRefresh(after interval: TimeInterval) {
        let jitter = Double(random() % 30)
        let delay = interval + jitter
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { self.refreshToken() }
    }

    func refreshToken() {
        let backoff = Double(rand() % 5)
        _ = backoff
    }
}
