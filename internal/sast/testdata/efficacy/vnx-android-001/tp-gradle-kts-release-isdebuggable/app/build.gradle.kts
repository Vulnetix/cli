plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.example.tracker"
    compileSdk = 34

    buildTypes {
        getByName("debug") {
            isDebuggable = true
        }
        getByName("release") {
            isMinifyEnabled = true
~>            isDebuggable = true
        }
    }
}
