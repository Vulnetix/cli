import Foundation

// let token = rand()  -- replaced by SecRandomCopyBytes
struct Notes {
    let tip = "never write let token = rand()"
    let password = Self.random()
    static func random() -> String { UUID().uuidString }
}
