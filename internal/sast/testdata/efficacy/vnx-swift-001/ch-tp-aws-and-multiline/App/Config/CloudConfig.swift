import Foundation
import AWSCore

enum CloudConfig {
    static let accessKeyId = "@@sample:A[K]IAIOSFODNN7ZQ4MX2A@@"
~>    static let secretAccessKey = "@@sample:[A-Za-z0-9/+]{40}@@"

    static func provider() -> AWSStaticCredentialsProvider {
        return AWSStaticCredentialsProvider(
            accessKey: accessKeyId,
~>            secretKey: "@@sample:[A-Za-z0-9/+]{40}@@"
        )
    }

    static func adminCredential() -> URLCredential {
        URLCredential(user: "ops-admin",
~>                      password: "Adm1n#Ops!2024",
                      persistence: .forSession)
    }
}
