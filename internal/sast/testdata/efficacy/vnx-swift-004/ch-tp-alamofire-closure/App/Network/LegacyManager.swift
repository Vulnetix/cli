import Alamofire

final class LegacyManager {
    let manager: SessionManager

    init() {
        let policies: [String: ServerTrustPolicy] = [
~>            "staging.acme.io": .disableEvaluation
        ]
        manager = SessionManager(serverTrustPolicyManager: ServerTrustPolicyManager(policies: policies))
        manager.delegate.sessionDidReceiveChallenge = { session, challenge in
~>            return (.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
        }
    }
}
