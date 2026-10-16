import XCTest
import Alamofire

final class NetTests: XCTestCase {
    func testLocal() {
        let ev = DisabledTrustEvaluator()
        let c = URLCredential(trust: trust)
        XCTAssertNotNil(ev); XCTAssertNotNil(c)
    }
}
