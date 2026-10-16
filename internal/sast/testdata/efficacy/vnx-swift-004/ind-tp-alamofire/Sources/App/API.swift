import Alamofire

let manager = Session(
    serverTrustManager: ServerTrustManager(evaluators: [
~>        "dev.example.com": DisabledTrustEvaluator()
    ])
)
