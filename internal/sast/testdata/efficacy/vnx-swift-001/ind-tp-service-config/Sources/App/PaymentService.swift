import Foundation

final class PaymentService {
    private let session = URLSession(configuration: .default)
~>    private let merchantSecret: String = "mZ4q9TxL81bVw0RcYe2sNd7H"
    var endpoint = URL(string: "https://pay.example.com/v1")!

    func charge(amount: Int) {
        var req = URLRequest(url: endpoint)
~>        req.setValue("Bearer 8f3kQz1LmP0xT7vRb2YcWd9Ae5", forHTTPHeaderField: "Authorization")
        session.dataTask(with: req).resume()
    }
}
