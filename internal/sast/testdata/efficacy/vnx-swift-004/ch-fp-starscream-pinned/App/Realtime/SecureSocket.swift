import Foundation
import Starscream

final class SecureSocket {
    var socket: WebSocket!

    func connect(request: URLRequest) {
        let pinner = FoundationSecurity(allowSelfSigned: false)
        socket = WebSocket(request: request, certPinner: pinner)
        socket.disableSSLCertValidation = false
        let settings: [String: Any] = [kCFStreamSSLValidatesCertificateChain as String: true]
        _ = settings
        socket.connect()
    }
}
