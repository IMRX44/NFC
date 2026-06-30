package com.nfcsecurity.analyzer.ui.report

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import com.google.gson.Gson
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.core.report.ReportGenerator
import com.nfcsecurity.analyzer.databinding.ActivityReportBinding
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class ReportActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REPORT_JSON = "extra_report_json"
    }

    private lateinit var binding: ActivityReportBinding

    @Inject
    lateinit var reportGenerator: ReportGenerator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityReportBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.export_report)

        val reportJson = intent.getStringExtra(EXTRA_REPORT_JSON)
        val report = try {
            Gson().fromJson(reportJson, FullReport::class.java)
        } catch (_: Exception) { null }

        if (report == null) {
            Toast.makeText(this, "Invalid report data", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        val textReport = reportGenerator.generateTextReport(report)
        binding.tvReportPreview.text = textReport

        binding.btnExportJson.setOnClickListener {
            try {
                val file = reportGenerator.generateJson(this, report)
                val uri = FileProvider.getUriForFile(
                    this,
                    "${packageName}.provider",
                    file
                )
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "application/json"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(shareIntent, "Share JSON Report"))
            } catch (e: Exception) {
                Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }

        binding.btnShareText.setOnClickListener {
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, textReport)
                putExtra(Intent.EXTRA_SUBJECT, "NFC Security Report - ${report.cardInfo.uid}")
            }
            startActivity(Intent.createChooser(shareIntent, "Share Report"))
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
