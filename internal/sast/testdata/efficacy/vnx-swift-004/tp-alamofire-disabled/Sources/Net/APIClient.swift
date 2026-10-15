import Alamofire

enum APIClient {
    static let evaluators: [String: ServerTrustEvaluating] = [
~>        "api.example.org": DisabledTrustEvaluator(),
~>        "legacy.example.org": DisabledEvaluator()
    ]
    static let session = Session(serverTrustManager: ServerTrustManager(evaluators: evaluators))

    static let policies: [String: ServerTrustPolicy] = [
~>        "old.example.org": .disableEvaluation
    ]
}
