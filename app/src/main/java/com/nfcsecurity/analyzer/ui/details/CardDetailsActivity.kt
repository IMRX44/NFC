package com.nfcsecurity.analyzer.ui.details

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.databinding.ActivityCardDetailsBinding
import com.nfcsecurity.analyzer.ui.attack.AttackActivity
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCardDetailsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val uid = intent.getStringExtra(EXTRA_UID) ?: "--"
        val cardType = intent.getStringExtra(EXTRA_CARD_TYPE) ?: "Unknown"
        val riskLevel = intent.getStringExtra(EXTRA_RISK_LEVEL) ?: "--"
        val grade = intent.getStringExtra(EXTRA_SECURITY_GRADE) ?: "--"
        val encryption = intent.getStringExtra(EXTRA_ENCRYPTION) ?: "--"
        val manufacturer = intent.getStringExtra(EXTRA_MANUFACTURER) ?: "--"
        val memory = intent.getIntExtra(EXTRA_MEMORY, 0)
        val atqa = intent.getStringExtra(EXTRA_ATQA) ?: "--"
        val sak = intent.getStringExtra(EXTRA_SAK) ?: "--"
        val reportJson = intent.getStringExtra(EXTRA_REPORT_JSON)

        binding.tvCardTypeDetail.text = cardType
        binding.tvUidDetail.text = uid
        binding.tvManufacturerDetail.text = manufacturer
        binding.tvEncryptionDetail.text = encryption
        binding.tvAtqaDetail.text = atqa
        binding.tvSakDetail.text = sak
        binding.tvMemoryDetail.text = "$memory bytes"
        binding.tvGradeBadge.text = grade
        binding.tvRiskLevel.text = riskLevel

        val riskColor = when (riskLevel.uppercase()) {
            "CRITICAL" -> getColor(R.color.neon_red)
            "HIGH" -> getColor(R.color.neon_orange)
            "MEDIUM" -> getColor(R.color.neon_yellow)
            else -> getColor(R.color.neon_green)
        }
        binding.tvRiskLevel.setTextColor(riskColor)

        val gradeColor = when (grade) {
            "A+", "A" -> getColor(R.color.neon_green)
            "B" -> getColor(R.color.neon_yellow)
            "C" -> getColor(R.color.neon_orange)
            else -> getColor(R.color.neon_red)
        }
        binding.tvGradeBadge.setTextColor(gradeColor)

        binding.btnBack.setOnClickListener { finish() }

        binding.btnAttackFromDetails.setOnClickListener {
            val intent = Intent(this, AttackActivity::class.java).apply {
                putExtra(AttackActivity.EXTRA_UID, uid)
                putExtra(AttackActivity.EXTRA_CARD_TYPE, cardType)
            }
            startActivity(intent)
        }

        binding.btnExportFromDetails.setOnClickListener {
            if (reportJson != null) {
                val intent = Intent(this, ReportActivity::class.java).apply {
                    putExtra("report_json", reportJson)
                }
                startActivity(intent)
            }
        }
    }
}
