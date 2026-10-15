import Foundation

enum Segue {
    static let showPassword = "showPasswordSegue"
    static let resetPassword = "resetPasswordViewController"
}

extension Notification.Name {
    static let refreshToken = Notification.Name("RefreshTokenDidChangeNotification")
}

enum NotificationKeys {
    static let refreshToken = "RefreshTokenDidChangeNotification"
    static let deviceToken = "DeviceTokenRegistered"
}

enum Assets {
    static let token = "TokenIcon"
    static let password = "eye.slash.fill"
}
