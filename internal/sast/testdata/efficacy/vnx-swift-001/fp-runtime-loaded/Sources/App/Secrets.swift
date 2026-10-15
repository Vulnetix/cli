import Foundation

// let apiKey = "k3Jd9sLq02MZpXa7Vt4c"  -- removed, loaded from the Keychain now
/// Example: `let clientSecret = "@@sample:c[9]f1[e]2a[7]b3[d]84[c]6f[9]e0[a]1b[2]c3[d]4e[5]f6[0]@@"`
struct Secrets {
    let apiKey = Bundle.main.object(forInfoDictionaryKey: "API_KEY") as? String ?? ""
    let clientSecret = ProcessInfo.processInfo.environment["CLIENT_SECRET"]
    let password = try? Keychain.read(account: "db")
    let message = "the apiKey = \"value\" form is rejected by review"
}
