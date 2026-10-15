import SwiftyUserDefaults

extension DefaultsKeys {
    var authToken: DefaultsKey<String?> { .init("authToken") }
    var onboardingDone: DefaultsKey<Bool> { .init("onboardingDone", defaultValue: false) }
}

final class SessionStore {
    func persist(_ response: LoginResponse) {
~>        Defaults[\.authToken] = response.token
        Defaults[\.onboardingDone] = true
~>        Defaults[.authToken] = response.token
    }
}
