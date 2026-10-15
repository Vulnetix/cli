val gitSha: String = try {
    providers.exec { commandLine("git", "rev-parse", "HEAD") }.standardOutput.asText.get().trim()
~>} catch (e: KotlinNullPointerException) {
    "unknown"
}
