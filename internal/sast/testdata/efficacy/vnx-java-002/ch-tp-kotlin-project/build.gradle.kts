plugins {
    id("org.springframework.boot") version "3.3.4"
    kotlin("jvm") version "2.0.20"
    kotlin("plugin.spring") version "2.0.20"
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-web")
}
