import Foundation

func open(_ inStream: InputStream) {
    let settings: [String: Any] = [
~>        kCFStreamSSLValidatesCertificateChain as String: false
    ]
    inStream.setProperty(settings, forKey: Stream.PropertyKey(kCFStreamPropertySSLSettings as String))
~>    NSURLRequest.setAllowsAnyHTTPSCertificate(true, forHost: "internal.example.com")
}
