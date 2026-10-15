import XCTest
import Alamofire

final class TLSTests: XCTestCase {
    func testExpiredHostWithDisabledEvaluation() {
        let evaluators = ["expired.badssl.com": DisabledTrustEvaluator()]
        _ = evaluators
        // completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
