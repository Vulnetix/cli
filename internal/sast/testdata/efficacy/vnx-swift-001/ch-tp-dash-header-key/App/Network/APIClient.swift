import Foundation

final class APIClient {
    private let session = URLSession.shared

    func headers() -> [String: String] {
~>        return ["x-api-key": "@@sample:9[f]8e[7]d6[c]5b[4]a3[9]28[1]70[6]f5[e]4d[3]c2[b]1a[0]@@",
                "Accept": "application/json"]
    }

    func send(_ request: inout URLRequest) {
~>        request.setValue("@@sample:Q[m]9v[d]HN[0]cm[F]wS[2]V5[M]jA[y]NA[7]7@@", forHTTPHeaderField: "X-Api-Key")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
}
