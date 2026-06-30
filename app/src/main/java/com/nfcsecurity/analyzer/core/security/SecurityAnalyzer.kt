package com.nfcsecurity.analyzer.core.security

import com.nfcsecurity.analyzer.core.nfc.*
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SecurityAnalyzer @Inject constructor() {

    fun analyze(cardInfo: CardInfo): SecurityReport {
        val encryption = determineEncryption(cardInfo.cardType)
        val grade = determineSecurityGrade(cardInfo.cardType)
        val vulnerabilities = findVulnerabilities(cardInfo)
        val risks = assessRisks(cardInfo)
        val recommendations = buildRecommendations(cardInfo, vulnerabilities, risks)
        val overallRisk = calculateOverallRisk(vulnerabilities, risks)

        return SecurityReport(
            encryptionType = encryption,
            securityGrade = grade,
            vulnerabilities = vulnerabilities,
            risks = risks,
            recommendations = recommendations,
            overallRiskLevel = overallRisk,
            hasDefaultKeys = hasDefaultKeys(cardInfo.cardType),
            hasUnauthenticatedSectors = hasUnauthenticatedSectors(cardInfo.cardType),
            hasMisconfiguredAccess = hasMisconfiguredAccess(cardInfo.cardType),
            supportsSecureMessaging = supportsSecureMessaging(cardInfo.cardType)
        )
    }

    private fun determineEncryption(type: CardType): EncryptionType = when (type) {
        CardType.MIFARE_CLASSIC -> EncryptionType.TRIPLE_DES
        CardType.MIFARE_ULTRALIGHT -> EncryptionType.NONE
        CardType.MIFARE_ULTRALIGHT_C -> EncryptionType.TRIPLE_DES
        CardType.MIFARE_DESFIRE,
        CardType.MIFARE_DESFIRE_EV1 -> EncryptionType.AES_128
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> EncryptionType.AES_256
        CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> EncryptionType.NONE
        CardType.FELICA -> EncryptionType.DES
        else -> EncryptionType.NONE
    }

    private fun determineSecurityGrade(type: CardType): SecurityGrade = when (type) {
        CardType.MIFARE_CLASSIC -> SecurityGrade.LOW
        CardType.MIFARE_ULTRALIGHT -> SecurityGrade.LOW
        CardType.MIFARE_ULTRALIGHT_C -> SecurityGrade.MEDIUM
        CardType.MIFARE_DESFIRE,
        CardType.MIFARE_DESFIRE_EV1 -> SecurityGrade.MEDIUM
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> SecurityGrade.HIGH
        CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> SecurityGrade.LOW
        CardType.FELICA -> SecurityGrade.MEDIUM
        else -> SecurityGrade.LOW
    }

    private fun findVulnerabilities(cardInfo: CardInfo): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()

        when (cardInfo.cardType) {
            CardType.MIFARE_CLASSIC -> {
                vulns.add(Vulnerability(
                    title = "CRYPTO1 Weak Cipher",
                    description = "MIFARE Classic uses proprietary CRYPTO1 cipher which has known " +
                            "weaknesses. Attacks like Darkside and Nested Authentication allow " +
                            "key recovery within minutes.",
                    severity = RiskLevel.CRITICAL,
                    cvssScore = 9.1f
                ))
                vulns.add(Vulnerability(
                    title = "Sector Key Extraction Risk",
                    description = "Keys A and B can potentially be extracted using known " +
                            "cryptographic attacks without physical damage to the card.",
                    severity = RiskLevel.HIGH,
                    cvssScore = 7.5f
                ))
                vulns.add(Vulnerability(
                    title = "Potential Default Key Usage",
                    description = "Many deployed MIFARE Classic cards still use default keys " +
                            "(0xFFFFFFFFFFFF or 0x000000000000), making them trivially readable.",
                    severity = RiskLevel.HIGH,
                    cvssScore = 8.2f
                ))
            }
            CardType.MIFARE_ULTRALIGHT -> {
                vulns.add(Vulnerability(
                    title = "No Authentication",
                    description = "MIFARE Ultralight has no authentication mechanism. Any NFC " +
                            "reader can access all memory pages without restriction.",
                    severity = RiskLevel.HIGH,
                    cvssScore = 8.0f
                ))
                vulns.add(Vulnerability(
                    title = "No Encryption",
                    description = "Data is stored in plaintext. Any reader can access the full " +
                            "card content.",
                    severity = RiskLevel.MEDIUM,
                    cvssScore = 5.5f
                ))
            }
            CardType.MIFARE_DESFIRE,
            CardType.MIFARE_DESFIRE_EV1 -> {
                vulns.add(Vulnerability(
                    title = "DES/3DES Legacy Support",
                    description = "DESFire EV1 supports legacy DES and 3DES modes which are " +
                            "considered outdated. Ensure AES mode is enforced.",
                    severity = RiskLevel.MEDIUM,
                    cvssScore = 5.0f
                ))
            }
            CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> {
                vulns.add(Vulnerability(
                    title = "No Sector Authentication",
                    description = "NTAG series does not support sector-level authentication. " +
                            "Password protection (if configured) is the only access control.",
                    severity = RiskLevel.MEDIUM,
                    cvssScore = 5.3f
                ))
                vulns.add(Vulnerability(
                    title = "NDEF Spoofing Risk",
                    description = "Without write protection, NDEF records can be overwritten by " +
                            "any writer, enabling phishing or malicious redirects.",
                    severity = RiskLevel.HIGH,
                    cvssScore = 7.0f
                ))
            }
            else -> {}
        }

        // Check NDEF for suspicious content
        cardInfo.ndefRecords.filter { it.isSuspicious }.forEach {
            vulns.add(Vulnerability(
                title = "Suspicious NDEF Content",
                description = "Suspicious data detected in NDEF record: ${it.suspiciousReason}",
                severity = RiskLevel.MEDIUM,
                cvssScore = 5.0f
            ))
        }

        return vulns
    }

    private fun assessRisks(cardInfo: CardInfo): List<RiskItem> {
        val risks = mutableListOf<RiskItem>()

        risks.add(RiskItem(
            category = RiskCategory.CLONEABILITY,
            level = getCloneabilityRisk(cardInfo.cardType),
            explanation = getCloneabilityExplanation(cardInfo.cardType)
        ))
        risks.add(RiskItem(
            category = RiskCategory.REPLAY_ATTACK,
            level = getReplayRisk(cardInfo.cardType),
            explanation = getReplayExplanation(cardInfo.cardType)
        ))
        risks.add(RiskItem(
            category = RiskCategory.UID_AUTH,
            level = getUidAuthRisk(cardInfo.cardType),
            explanation = "UID-based authentication is insecure; UIDs can be emulated by commercial tools."
        ))
        risks.add(RiskItem(
            category = RiskCategory.MISCONFIGURATION,
            level = getMisconfigRisk(cardInfo.cardType),
            explanation = getMisconfigExplanation(cardInfo.cardType)
        ))
        risks.add(RiskItem(
            category = RiskCategory.SECURE_MESSAGING,
            level = getSecureMessagingRisk(cardInfo.cardType),
            explanation = getSecureMessagingExplanation(cardInfo.cardType)
        ))
        risks.add(RiskItem(
            category = RiskCategory.DEFAULT_KEYS,
            level = getDefaultKeyRisk(cardInfo.cardType),
            explanation = getDefaultKeyExplanation(cardInfo.cardType)
        ))

        return risks
    }

    private fun getCloneabilityRisk(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> RiskLevel.CRITICAL
        CardType.MIFARE_ULTRALIGHT -> RiskLevel.HIGH
        CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> RiskLevel.HIGH
        CardType.MIFARE_ULTRALIGHT_C -> RiskLevel.MEDIUM
        CardType.MIFARE_DESFIRE_EV1 -> RiskLevel.MEDIUM
        CardType.MIFARE_DESFIRE_EV2, CardType.MIFARE_DESFIRE_EV3 -> RiskLevel.LOW
        else -> RiskLevel.MEDIUM
    }

    private fun getCloneabilityExplanation(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> "MIFARE Classic cards are easily cloneable using widely " +
                "available tools (Proxmark, ChameleonMini). The CRYPTO1 cipher provides minimal protection."
        CardType.MIFARE_ULTRALIGHT -> "No authentication; card can be fully copied with a standard NFC reader."
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> "Strong AES encryption and mutual authentication make cloning extremely difficult."
        else -> "Moderate cloning resistance depending on key management."
    }

    private fun getReplayRisk(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> RiskLevel.HIGH
        CardType.MIFARE_ULTRALIGHT -> RiskLevel.HIGH
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> RiskLevel.LOW
        else -> RiskLevel.MEDIUM
    }

    private fun getReplayExplanation(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> "Without secure messaging, captured transactions can be replayed."
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> "Transaction MAC and session keys prevent replay attacks."
        else -> "Replay risk depends on application-level implementation."
    }

    private fun getUidAuthRisk(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC,
        CardType.MIFARE_ULTRALIGHT,
        CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> RiskLevel.HIGH
        else -> RiskLevel.MEDIUM
    }

    private fun getMisconfigRisk(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> RiskLevel.HIGH
        CardType.MIFARE_ULTRALIGHT -> RiskLevel.LOW
        CardType.MIFARE_DESFIRE_EV1 -> RiskLevel.MEDIUM
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> RiskLevel.LOW
        else -> RiskLevel.MEDIUM
    }

    private fun getMisconfigExplanation(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> "Access bits for each sector can be misconfigured, leaving data " +
                "readable without Key A authentication."
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> "Fine-grained access control reduces misconfiguration risk."
        else -> "Configuration complexity varies; review application documentation."
    }

    private fun getSecureMessagingRisk(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC,
        CardType.MIFARE_ULTRALIGHT,
        CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> RiskLevel.HIGH
        CardType.MIFARE_DESFIRE_EV1 -> RiskLevel.MEDIUM
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> RiskLevel.LOW
        else -> RiskLevel.HIGH
    }

    private fun getSecureMessagingExplanation(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> "No secure messaging support. Data transmitted in plaintext."
        CardType.MIFARE_DESFIRE_EV2,
        CardType.MIFARE_DESFIRE_EV3 -> "Supports AES-based secure messaging with CommitReaderID."
        else -> "Limited or no secure messaging capabilities."
    }

    private fun getDefaultKeyRisk(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> RiskLevel.CRITICAL
        CardType.MIFARE_ULTRALIGHT_C -> RiskLevel.MEDIUM
        CardType.MIFARE_DESFIRE,
        CardType.MIFARE_DESFIRE_EV1 -> RiskLevel.MEDIUM
        else -> RiskLevel.LOW
    }

    private fun getDefaultKeyExplanation(type: CardType) = when (type) {
        CardType.MIFARE_CLASSIC -> "MIFARE Classic cards are frequently deployed with factory-default " +
                "keys (0xFF*6 or 0x00*6), enabling full card compromise with standard tools."
        CardType.MIFARE_DESFIRE -> "DESFire default transport key (0x00*16) must be changed before deployment."
        else -> "Default key risk is minimal for this card type."
    }

    private fun buildRecommendations(
        cardInfo: CardInfo,
        vulns: List<Vulnerability>,
        risks: List<RiskItem>
    ): List<String> {
        val recs = mutableListOf<String>()

        when (cardInfo.cardType) {
            CardType.MIFARE_CLASSIC -> {
                recs.add("Migrate to MIFARE DESFire EV2/EV3 or a FIDO-compatible smart card for security-critical applications.")
                recs.add("If migration is not possible, ensure non-default keys are deployed and rotate them periodically.")
                recs.add("Implement application-level encryption and integrity checks independent of the card.")
                recs.add("Consider adding server-side validation to prevent cloned card acceptance.")
            }
            CardType.MIFARE_ULTRALIGHT -> {
                recs.add("Use NTAG21x with password protection for applications requiring any access control.")
                recs.add("Do not store sensitive or personally identifiable information on this card.")
                recs.add("Consider upgrading to MIFARE DESFire for secure deployments.")
            }
            CardType.MIFARE_DESFIRE_EV1 -> {
                recs.add("Enforce AES-128 mode and disable DES/3DES legacy support.")
                recs.add("Enable Secure Messaging for all sensitive transactions.")
                recs.add("Upgrade to EV2/EV3 for enhanced security features including Transaction MAC.")
            }
            CardType.MIFARE_DESFIRE_EV2,
            CardType.MIFARE_DESFIRE_EV3 -> {
                recs.add("Ensure Transaction MAC (CommitReaderID) is enabled for all financial transactions.")
                recs.add("Use AES-256 where supported and regularly rotate application keys.")
                recs.add("Enable Proximity Check to prevent relay attacks.")
            }
            CardType.NTAG213, CardType.NTAG215, CardType.NTAG216 -> {
                recs.add("Enable password protection and write protection for all NDEF records.")
                recs.add("Do not use NTAG for authentication-critical applications.")
                recs.add("Validate NDEF content server-side to prevent NDEF injection attacks.")
            }
            else -> {
                recs.add("Consult the card manufacturer's security guidelines for this card type.")
            }
        }

        if (risks.any { it.category == RiskCategory.UID_AUTH && it.level != RiskLevel.LOW }) {
            recs.add("Never rely on UID alone for authentication — UIDs can be emulated.")
        }
        if (cardInfo.ndefRecords.any { it.isSuspicious }) {
            recs.add("Suspicious NDEF content detected. Investigate before trusting card data.")
        }

        return recs
    }

    private fun calculateOverallRisk(
        vulns: List<Vulnerability>,
        risks: List<RiskItem>
    ): RiskLevel {
        val hasCritical = vulns.any { it.severity == RiskLevel.CRITICAL } ||
                risks.any { it.level == RiskLevel.CRITICAL }
        val hasHigh = vulns.any { it.severity == RiskLevel.HIGH } ||
                risks.any { it.level == RiskLevel.HIGH }
        val hasMedium = vulns.any { it.severity == RiskLevel.MEDIUM } ||
                risks.any { it.level == RiskLevel.MEDIUM }
        return when {
            hasCritical -> RiskLevel.CRITICAL
            hasHigh -> RiskLevel.HIGH
            hasMedium -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }

    private fun hasDefaultKeys(type: CardType) = type == CardType.MIFARE_CLASSIC ||
            type == CardType.MIFARE_DESFIRE || type == CardType.MIFARE_DESFIRE_EV1

    private fun hasUnauthenticatedSectors(type: CardType) = type == CardType.MIFARE_ULTRALIGHT ||
            type == CardType.NTAG213 || type == CardType.NTAG215 || type == CardType.NTAG216

    private fun hasMisconfiguredAccess(type: CardType) = type == CardType.MIFARE_CLASSIC

    private fun supportsSecureMessaging(type: CardType) = type == CardType.MIFARE_DESFIRE_EV1 ||
            type == CardType.MIFARE_DESFIRE_EV2 || type == CardType.MIFARE_DESFIRE_EV3
}
