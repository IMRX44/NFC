package com.nfcsecurity.analyzer.core.report

import android.content.Context
import com.google.gson.GsonBuilder
import com.nfcsecurity.analyzer.core.nfc.CardInfo
import com.nfcsecurity.analyzer.core.security.SecurityReport
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import javax.inject.Inject
import javax.inject.Singleton

data class FullReport(
    val cardInfo: CardInfo,
    val securityReport: SecurityReport,
    val generatedAt: String,
    val toolVersion: String = "1.0.0"
)

@Singleton
class ReportGenerator @Inject constructor() {

    private val gson = GsonBuilder().setPrettyPrinting().serializeNulls().create()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
    private val fileNameFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)

    fun generateJson(context: Context, report: FullReport): File {
        val dir = getReportsDir(context)
        val fileName = "nfc_report_${fileNameFormat.format(Date())}.json"
        val file = File(dir, fileName)

        val jsonData = mapOf(
            "report_metadata" to mapOf(
                "tool" to "NFC Security Analyzer",
                "version" to report.toolVersion,
                "generated_at" to report.generatedAt
            ),
            "card_information" to mapOf(
                "uid" to report.cardInfo.uid,
                "card_type" to report.cardInfo.cardType.displayName,
                "protocol" to report.cardInfo.cardType.protocol,
                "manufacturer" to report.cardInfo.manufacturer,
                "memory_capacity" to report.cardInfo.memoryCapacity,
                "atqa" to report.cardInfo.atqa,
                "sak" to report.cardInfo.sak,
                "technologies" to report.cardInfo.technologies,
                "ndef_records" to report.cardInfo.ndefRecords.map { rec ->
                    mapOf(
                        "type" to rec.type.name,
                        "payload" to rec.payload,
                        "is_suspicious" to rec.isSuspicious,
                        "suspicious_reason" to rec.suspiciousReason
                    )
                }
            ),
            "security_assessment" to mapOf(
                "overall_risk" to report.securityReport.overallRiskLevel.label,
                "security_grade" to report.securityReport.securityGrade.label,
                "encryption_type" to report.securityReport.encryptionType.displayName,
                "has_default_keys" to report.securityReport.hasDefaultKeys,
                "has_unauthenticated_sectors" to report.securityReport.hasUnauthenticatedSectors,
                "has_misconfigured_access" to report.securityReport.hasMisconfiguredAccess,
                "supports_secure_messaging" to report.securityReport.supportsSecureMessaging
            ),
            "vulnerabilities" to report.securityReport.vulnerabilities.map { v ->
                mapOf(
                    "title" to v.title,
                    "description" to v.description,
                    "severity" to v.severity.label,
                    "cvss_score" to v.cvssScore
                )
            },
            "risk_assessment" to report.securityReport.risks.map { r ->
                mapOf(
                    "category" to r.category.displayName,
                    "level" to r.level.label,
                    "explanation" to r.explanation
                )
            },
            "recommendations" to report.securityReport.recommendations
        )

        file.writeText(gson.toJson(jsonData))
        return file
    }

    fun generateTextReport(report: FullReport): String {
        val sb = StringBuilder()
        val line = "═".repeat(60)
        val thinLine = "─".repeat(60)

        sb.appendLine(line)
        sb.appendLine("  NFC SECURITY ASSESSMENT REPORT")
        sb.appendLine("  NFC Security Analyzer v${report.toolVersion}")
        sb.appendLine("  Generated: ${report.generatedAt}")
        sb.appendLine(line)
        sb.appendLine()

        sb.appendLine("▌ CARD INFORMATION")
        sb.appendLine(thinLine)
        sb.appendLine("  UID              : ${report.cardInfo.uid}")
        sb.appendLine("  Card Type        : ${report.cardInfo.cardType.displayName}")
        sb.appendLine("  Protocol         : ${report.cardInfo.cardType.protocol}")
        sb.appendLine("  Manufacturer     : ${report.cardInfo.manufacturer}")
        sb.appendLine("  Memory           : ${report.cardInfo.memoryCapacity}")
        sb.appendLine("  ATQA             : ${report.cardInfo.atqa ?: "N/A"}")
        sb.appendLine("  SAK              : ${report.cardInfo.sak ?: "N/A"}")
        sb.appendLine("  Technologies     : ${report.cardInfo.technologies.joinToString(", ")}")
        sb.appendLine()

        sb.appendLine("▌ SECURITY ASSESSMENT")
        sb.appendLine(thinLine)
        sb.appendLine("  Overall Risk     : ${report.securityReport.overallRiskLevel.label}")
        sb.appendLine("  Security Grade   : ${report.securityReport.securityGrade.label}")
        sb.appendLine("  Encryption       : ${report.securityReport.encryptionType.displayName}")
        sb.appendLine("  Default Keys     : ${if (report.securityReport.hasDefaultKeys) "RISK PRESENT" else "Not Applicable"}")
        sb.appendLine("  Unauth. Sectors  : ${if (report.securityReport.hasUnauthenticatedSectors) "YES" else "NO"}")
        sb.appendLine("  Secure Messaging : ${if (report.securityReport.supportsSecureMessaging) "Supported" else "Not Supported"}")
        sb.appendLine()

        sb.appendLine("▌ VULNERABILITIES (${report.securityReport.vulnerabilities.size} found)")
        sb.appendLine(thinLine)
        report.securityReport.vulnerabilities.forEachIndexed { i, v ->
            sb.appendLine("  [${i + 1}] ${v.title}")
            sb.appendLine("      Severity : ${v.severity.label} (CVSS ${v.cvssScore})")
            sb.appendLine("      ${v.description}")
            sb.appendLine()
        }

        sb.appendLine("▌ RISK MATRIX")
        sb.appendLine(thinLine)
        report.securityReport.risks.forEach { r ->
            sb.appendLine("  ${r.category.displayName.padEnd(30)} [${r.level.label.uppercase()}]")
        }
        sb.appendLine()

        sb.appendLine("▌ RECOMMENDATIONS")
        sb.appendLine(thinLine)
        report.securityReport.recommendations.forEachIndexed { i, rec ->
            sb.appendLine("  ${i + 1}. $rec")
            sb.appendLine()
        }

        if (report.cardInfo.ndefRecords.isNotEmpty()) {
            sb.appendLine("▌ NDEF RECORDS")
            sb.appendLine(thinLine)
            report.cardInfo.ndefRecords.forEachIndexed { i, rec ->
                sb.appendLine("  [${i + 1}] Type: ${rec.type.name}")
                sb.appendLine("      Payload: ${rec.payload.take(80)}${if (rec.payload.length > 80) "..." else ""}")
                if (rec.isSuspicious) sb.appendLine("      ⚠ WARNING: ${rec.suspiciousReason}")
                sb.appendLine()
            }
        }

        sb.appendLine(line)
        sb.appendLine("  END OF REPORT — FOR AUTHORIZED SECURITY ASSESSMENT ONLY")
        sb.appendLine(line)

        return sb.toString()
    }

    fun getReportsDir(context: Context): File {
        val dir = File(context.getExternalFilesDir(null), "NFCReports")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    fun buildFullReport(cardInfo: CardInfo, securityReport: SecurityReport): FullReport {
        return FullReport(
            cardInfo = cardInfo,
            securityReport = securityReport,
            generatedAt = dateFormat.format(Date())
        )
    }
}
