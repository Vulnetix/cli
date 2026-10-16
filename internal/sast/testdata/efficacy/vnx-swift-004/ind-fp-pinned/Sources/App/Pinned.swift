import Foundation
import Alamofire

final class Pinner: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

let m = ServerTrustManager(evaluators: ["api.example.com": PinnedCertificatesTrustEvaluator()])
let d = ServerTrustManager(evaluators: ["x.example.com": DefaultTrustEvaluator()])
let basic = URLCredential(user: "u", password: "p", persistence: .forSession)
