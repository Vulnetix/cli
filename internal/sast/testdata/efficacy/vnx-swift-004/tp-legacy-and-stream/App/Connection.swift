import Foundation

class Connection: NSObject, NSURLConnectionDelegate {
    func connection(_ connection: NSURLConnection, willSendRequestFor challenge: URLAuthenticationChallenge) {
~>        challenge.sender?.use(URLCredential(trust: challenge.protectionSpace.serverTrust!), for: challenge)
    }

    func openStream(_ input: InputStream) {
        let settings: [String: Any] = [
~>            kCFStreamSSLValidatesCertificateChain as String: kCFBooleanFalse as Any,
        ]
        input.setProperty(settings, forKey: Stream.PropertyKey(kCFStreamPropertySSLSettings as String))
    }
}
