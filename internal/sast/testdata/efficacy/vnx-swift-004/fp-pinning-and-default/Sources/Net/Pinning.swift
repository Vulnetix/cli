import Foundation
import Alamofire

final class PinningDelegate: NSObject, URLSessionDelegate {
    let pinnedCertificate: Data

    init(pinnedCertificate: Data) { self.pinnedCertificate = pinnedCertificate }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            return completionHandler(.cancelAuthenticationChallenge, nil)
        }
        let serverCertificate = SecCertificateCopyData(certificate) as Data
        if serverCertificate == pinnedCertificate {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

let basic = URLCredential(user: "svc", password: passwordFromKeychain(), persistence: .forSession)
let manager = ServerTrustManager(evaluators: ["api.example.org": PinnedCertificatesTrustEvaluator()])
let note = "DisabledTrustEvaluator() must never ship"
