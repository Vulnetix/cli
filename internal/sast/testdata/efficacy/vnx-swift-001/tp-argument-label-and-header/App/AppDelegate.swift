import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
~>        @@sample:A[n]al[y]ti[c]s[.][s]ta[r]tS[e]ss[i]on@@(apiKey: "@@sample:Q[7]RM[2]HP[6]28[8]5A[Q]XF[K]ZD[X]@@", options: .default)
        var request = URLRequest(url: URL(string: "https://api.example.com/me")!)
~>        request.setValue("Bearer @@sample:e[y]JhbGciOiJIUzI1NiJ9[.]c3ViMTIz[.]abcDEF123456@@", forHTTPHeaderField: "Authorization")
        let login = LoginRequest(username: "svc-sync",
~>                                 password: "Winter2024!x")
        _ = login
        return true
    }
}
