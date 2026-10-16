import Foundation

// Never use DisabledTrustEvaluator() in production
let warning = "Do not call URLCredential(trust: t) blindly or set kCFStreamSSLValidatesCertificateChain to false"
/* NSURLRequest.setAllowsAnyHTTPSCertificate(true, forHost: h) */
final class DisabledTrustEvaluator2 {}
