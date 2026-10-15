plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.acme.shop"
    compileSdk = 34

    buildTypes {
        getByName("debug") {
            isDebuggable = true
        }
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
~>            isDebuggable = true
        }
    }
}
