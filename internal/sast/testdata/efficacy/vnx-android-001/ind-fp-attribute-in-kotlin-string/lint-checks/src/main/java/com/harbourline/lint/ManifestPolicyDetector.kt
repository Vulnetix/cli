package com.harbourline.lint

import com.android.tools.lint.detector.api.Category
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.Severity

object ManifestPolicyDetector {
    private const val DEBUGGABLE_SNIPPET = "android:debuggable=\"true\""
    private const val BACKUP_SNIPPET = "android:allowBackup=\"true\""

    val ISSUE: Issue = Issue.create(
        id = "ReleaseManifestPolicy",
        briefDescription = "Release manifest must not contain $DEBUGGABLE_SNIPPET",
        explanation = "Remove android:debuggable=\"true\" and android:allowBackup=\"true\" from the release manifest.",
        category = Category.SECURITY,
        priority = 8,
        severity = Severity.ERROR,
        implementation = TODO()
    )

    fun violates(manifestText: String): Boolean =
        manifestText.contains(DEBUGGABLE_SNIPPET) || manifestText.contains(BACKUP_SNIPPET)
}
