plugins {
    kotlin("jvm") version "1.9.24"
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib")
~>    implementation("log4j:log4j:1.2.17")
~>    implementation("commons-httpclient:commons-httpclient:3.1")
~>    implementation("org.codehaus.jackson:jackson-core-asl:1.9.13")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.1")
}
