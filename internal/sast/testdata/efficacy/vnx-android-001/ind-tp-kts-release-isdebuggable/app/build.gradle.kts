plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "io.quayside.tickets"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.quayside.tickets"
        minSdk = 26
        targetSdk = 34
        versionCode = 108
        versionName = "5.1.2"
    }

    buildTypes {
        getByName("debug") {
            isDebuggable = true
        }
        getByName("release") {
            isMinifyEnabled = true
~>            isDebuggable = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
