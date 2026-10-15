import Foundation

final class Session {
    var apiSecret: String?

    func configure() {
~>        self.apiSecret = "S3cr3tV4lu3Q9z"
        let body: [String: Any] = [
            "username": "sync-bot",
~>            "password": "Pa55w0rd!2023",
        ]
        var request = URLRequest(url: URL(string: "https://example.org/login")!)
~>        @@sample:r[e]qu[e]st[.]se[t]Va[l]ue@@("Basic @@sample:c[3]lu[Y]y1[i]b3[Q]6U[G]E1[N]Xc[w]cm[Q]hM[j]Ay[M]w[=][=]@@", @@sample:f[o]rH[T]TP[H]ea[d]er[F]ie[l]d@@: "Authorization")
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    }
}
