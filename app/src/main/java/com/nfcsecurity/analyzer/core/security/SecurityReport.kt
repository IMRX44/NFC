package com.nfcsecurity.analyzer.core.security

import com.nfcsecurity.analyzer.core.nfc.EncryptionType
import com.nfcsecurity.analyzer.core.nfc.RiskLevel
import com.nfcsecurity.analyzer.core.nfc.SecurityGrade

data class SecurityReport(
    val encryptionType: EncryptionType,
    val securityGrade: SecurityGrade,
    val vulnerabilities: List<Vulnerability>,
    val risks: List<RiskItem>,
    val recommendations: List<String>,
    val overallRiskLevel: RiskLevel,
    val hasDefaultKeys: Boolean,
    val hasUnauthenticatedSectors: Boolean,
    val hasMisconfiguredAccess: Boolean,
    val supportsSecureMessaging: Boolean
)

data class Vulnerability(
    val title: String,
    val description: String,
    val severity: RiskLevel,
    val cvssScore: Float
)

data class RiskItem(
    val category: RiskCategory,
    val level: RiskLevel,
    val explanation: String
)

enum class RiskCategory(val displayName: String) {
    CLONEABILITY("Cloneability Risk"),
    REPLAY_ATTACK("Replay Attack Risk"),
    UID_AUTH("UID-based Auth Risk"),
    MISCONFIGURATION("Misconfiguration Risk"),
    SECURE_MESSAGING("Secure Messaging Risk"),
    DEFAULT_KEYS("Default Keys Risk"),
    DATA_EXPOSURE("Data Exposure Risk")
}
