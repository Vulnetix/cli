import Foundation

final class APIClient {
~>    private let apiKey = "@@sample:k[3]Jd[9]sL[q]02[M]Zp[X]a7[V]t4[c]@@"
~>    static let clientSecret: String = "@@sample:c[9]f1[e]2a[7]b3[d]84[c]6f[9]e0[a]1b[2]c3[d]4e[5]f6[0]@@"
    let baseURL = URL(string: "https://api.example.com")!

    func request(_ path: String) -> URLRequest {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        return req
    }
}
