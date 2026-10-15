plugins {
    kotlin("jvm") version "1.9.22"
}

dependencies {
~>    implementation("org.apache.commons:commons-text:1.8")
~>    implementation(group = "@@sample:o[r]g[.][a]pa[c]he[.]lo[g]gi[n]g[.][l]og[4]j@@", name = "log4j-core", version = "2.13.3")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}
