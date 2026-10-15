import Foundation

struct TokenFactory {
    func make() -> String {
        srand48(Int(Date()@@sample:[.][t]im[e]In[t]er[v]al[S]in[c]e1[9]70@@))
~>        let resetToken = String(rand(), radix: 16)
~>        let salt = drand48()
        let token = (0..<16).map { _ in
~>            String(format: "%02x", random() % 256)
        }.joined()
        return resetToken + "\(salt)" + token
    }
}
