import Foundation
import CocoaLumberjackSwift

final class TokenStore {
    func save(accessToken: String, refreshToken: String) {
~>        DDLogDebug("Saving access token \(accessToken)")
~>        DDLogInfo("refresh=" + refreshToken)
        DDLogInfo("Tokens saved")
    }
}
