import Foundation

struct AdminGate {
~>    static let masterKey = "d41Xz9QpL02mVtRcY7bNwKeA"

    func check(_ password: String) -> Bool {
~>        if password == "hunter2Admin!x" { return true }
        return false
    }
}
