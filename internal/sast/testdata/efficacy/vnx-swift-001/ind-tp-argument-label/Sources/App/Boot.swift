import UIKit

class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions opts: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        Crashes.start(
~>            apiKey: "tR8nQ2vLx0Pz7MbK4cYd1WeJ",
            options: .default
        )
        let creds = [
            "username": "svc-mobile",
~>            "password": "Qm7!xv2Lp9ZaR4tK"
        ]
        return true
    }
}
