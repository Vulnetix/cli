import Foundation
import Starscream

final class SocketClient {
    var socket: WebSocket!

    func connectLegacy(url: URL) {
        socket = WebSocket(url: url)
~>        socket.disableSSLCertValidation = true
        socket.connect()
    }

    func connect(request: URLRequest) {
~>        let pinner = FoundationSecurity(allowSelfSigned: true)
        socket = WebSocket(request: request, certPinner: pinner)
        socket.connect()
    }
}
