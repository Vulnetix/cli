import Foundation

struct PasswordReset {
    func makeResetCode() -> String {
~>        let n = Int(random() % 900_000) + 100_000
        return String(n)
    }

    func makeVerificationCode() -> String {
        srand48(Int(Date()@@sample:[.][t]im[e]In[t]er[v]al[S]in[c]e1[9]70@@))
~>        let value = Int(drand48() * 1_000_000)
        return String(format: "%06d", value)
    }
}
