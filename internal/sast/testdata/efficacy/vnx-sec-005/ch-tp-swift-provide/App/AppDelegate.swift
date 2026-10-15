import GoogleMaps

class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
~>        GMSServices.provideAPIKey("@@sample:AIza[0-9A-Za-z_-]{35}@@")
        return true
    }
}
