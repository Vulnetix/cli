import Foundation

final class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
~>            completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }
}

final class HostDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard let trust = challenge.protectionSpace.serverTrust else { return (.performDefaultHandling, nil) }
        if challenge.protectionSpace.host == "staging.example.org" {
~>            let credential = URLCredential(trust: trust)
            return (.useCredential, credential)
        }
        return (.performDefaultHandling, nil)
    }
}
