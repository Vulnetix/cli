import Foundation

final class LegacyTrust: NSObject, NSURLConnectionDelegate {
    func connection(_ connection: NSURLConnection, willSendRequestFor challenge: URLAuthenticationChallenge) {
        guard let trust = challenge.protectionSpace.serverTrust else { return }
        var result = SecTrustResultType.invalid
        SecTrustEvaluate(trust, &result)
        if result == .proceed || result == .unspecified {
            challenge.sender?.use(URLCredential(trust: trust), for: challenge)
        } else {
            challenge.sender?.cancel(challenge)
        }
    }
}
