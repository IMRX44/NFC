package com.nfcsecurity.analyzer.ui.details

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.databinding.ActivityCardDetailsBinding
import com.nfcsecurity.analyzer.ui.report.ReportActivity
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class CardDetailsActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_UID = "extra_uid"
        const val EXTRA_CARD_TYPE = "extra_card_type"
        const val EXTRA_RISK_LEVEL = "extra_risk_level"
        const val EXTRA_SECURITY_GRADE = "extra_security_grade"
        const val EXTRA_ENCRYPTION = "extra_encryption"
        const val EXTRA_MANUFACTURER = "extra_manufacturer"
        const val EXTRA_MEMORY = "extra_memory"
        const val EXTRA_ATQA = "extra_atqa"
        const val EXTRA_SAK = "extra_sak"
        const val EXTRA_REPORT_JSON = "extra_report_json"
    }

    private lateinit var binding: ActivityCardDetailsBinding
    private var fullReport: FullReport? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCardDetailsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Card Analysis"

        loadData()
        setupClickListeners()
    }

    private fun loadData() {
        val reportJson = intent.getStringExtra(EXTRA_REPORT_JSON)
        if (reportJson != null) {
            fullReport = try { Gson().fromJson(reportJson, FullReport::class.java) } catch (_: Exception) { null }
        }

        val cardType = intent.getStringExtra(EXTRA_CARD_TYPE) ?: "Unknown"
        val uid = intent.getStringExtra(EXTRA_UID) ?: "N/A"
        val riskLevel = intent.getStringExtra(EXTRA_RISK_LEVEL) ?: "Unknown"
        val grade = intent.getStringExtra(EXTRA_SECURITY_GRADE) ?: "Unknown"
        val encryption = intent.getStringExtra(EXTRA_ENCRYPTION) ?: "Unknown"
        val manufacturer = intent.getStringExtra(EXTRA_MANUFACTURER) ?: "Unknown"
        val memory = intent.getStringExtra(EXTRA_MEMORY) ?: "Unknown"
        val atqa = intent.getStringExtra(EXTRA_ATQA) ?: "N/A"
        val sak = intent.getStringExtra(EXTRA_SAK) ?: "N/A"

        // Card Info
        binding.tvCardType.text = cardType
        binding.tvUid.text = uid
        binding.tvManufacturer.text = manufacturer
        binding.tvMemory.text = memory
        binding.tvAtqa.text = atqa
        binding.tvSak.text = sak

        // Risk Badge
        binding.tvRiskBadge.text = riskLevel.uppercase()
        val riskColor = when (riskLevel.uppercase()) {
            "CRITICAL", "HIGH" -> getColor(R.color.risk_high)
            "MEDIUM" -> getColor(R.color.risk_medium)
            else -> getColor(R.color.risk_low)
        }
        binding.tvRiskBadge.setTextColor(riskColor)
        binding.riskIndicator.setBackgroundColor(riskColor)

        // Security section
        binding.tvSecurityGrade.text = grade
        binding.tvEncryption.text = encryption

        // Vulnerabilities
        fullReport?.securityReport?.vulnerabilities?.let { vulns ->
            if (vulns.isEmpty()) {
                binding.tvNoVulnerabilities.visibility = View.VISIBLE
                binding.containerVulnerabilities.visibility = View.GONE
            } else {
                binding.tvNoVulnerabilities.visibility = View.GONE
                binding.containerVulnerabilities.visibility = View.VISIBLE
                val sb = StringBuilder()
                vulns.forEach { v ->
                    sb.appendLine("▸ ${v.title}  [${v.severity.label} | CVSS ${v.cvssScore}]")
                    sb.appendLine("  ${v.description}")
                    sb.appendLine()
                }
                binding.tvVulnerabilities.text = sb.toString().trimEnd()
            }
        }

        // Risks
        fullReport?.securityReport?.risks?.let { risks ->
            val sb = StringBuilder()
            risks.forEach { r ->
                val indicator = when (r.level.label.uppercase()) {
                    "CRITICAL", "HIGH" -> "🔴"
                    "MEDIUM" -> "🟡"
                    else -> "🟢"
                }
                sb.appendLine("$indicator ${r.category.displayName.padEnd(30)} ${r.level.label.uppercase()}")
            }
            binding.tvRiskMatrix.text = sb.toString().trimEnd()
        }

        // Recommendations
        fullReport?.securityReport?.recommendations?.let { recs ->
            val sb = StringBuilder()
            recs.forEachIndexed { i, rec ->
                sb.appendLine("${i + 1}. $rec")
                sb.appendLine()
            }
            binding.tvRecommendations.text = sb.toString().trimEnd()
        }

        // NDEF
        fullReport?.cardInfo?.ndefRecords?.let { records ->
            if (records.isEmpty()) {
                binding.tvNdef.text = getString(R.string.no_ndef_records)
            } else {
                val sb = StringBuilder()
                records.forEachIndexed { i, rec ->
                    sb.appendLine("[${i + 1}] ${rec.type.name}: ${rec.payload.take(60)}${if (rec.payload.length > 60) "…" else ""}")
                    if (rec.isSuspicious) sb.appendLine("    ⚠ ${rec.suspiciousReason}")
                }
                binding.tvNdef.text = sb.toString().trimEnd()
            }
        }
    }

    private fun setupClickListeners() {
        binding.btnExportJson.setOnClickListener {
            fullReport?.let { report ->
                val intent = Intent(this, ReportActivity::class.java).apply {
                    putExtra(ReportActivity.EXTRA_REPORT_JSON, Gson().toJson(report))
                }
                startActivity(intent)
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
