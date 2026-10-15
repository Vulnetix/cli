android {
    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
        }
        debug {
            isDebuggable = true
            applicationIdSuffix = ".debug"
        }
        create("qa") {
            initWith(getByName("debug"))
            isDebuggable = true
        }
    }
}
