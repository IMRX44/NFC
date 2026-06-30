package com.nfcsecurity.analyzer.ui

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.view.View
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.databinding.ActivityMainBinding
import com.nfcsecurity.analyzer.ui.details.CardDetailsActivity
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()
    private var nfcAdapter: NfcAdapter? = null
    private lateinit var pendingIntent: PendingIntent

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        setupPendingIntent()
        setupObservers()
        setupClickListeners()
        checkNfcStatus()
    }

    private fun setupPendingIntent() {
        pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )
    }

    private fun setupObservers() {
        viewModel.scanState.observe(this) { state ->
            when (state) {
                is ScanState.Idle -> showIdleState()
                is ScanState.Scanning -> showScanningState()
                is ScanState.Success -> showSuccessState(state.report)
                is ScanState.Error -> showErrorState(state.message)
            }
        }
    }

    private fun setupClickListeners() {
        binding.btnViewHistory.setOnClickListener {
            startActivity(Intent(this, HistoryActivity::class.java))
        }
        binding.cardLastScan.setOnClickListener {
            // Navigate to details if there's a last scan
        }
        binding.btnRetry.setOnClickListener {
            viewModel.resetState()
        }
    }

    private fun checkNfcStatus() {
        when {
            nfcAdapter == null -> {
                binding.tvNfcStatus.text = getString(R.string.nfc_not_supported)
                binding.tvNfcStatus.setTextColor(getColor(R.color.risk_high))
            }
            !nfcAdapter!!.isEnabled -> {
                binding.tvNfcStatus.text = getString(R.string.nfc_disabled)
                binding.tvNfcStatus.setTextColor(getColor(R.color.risk_medium))
            }
            else -> {
                binding.tvNfcStatus.text = getString(R.string.nfc_ready)
                binding.tvNfcStatus.setTextColor(getColor(R.color.risk_low))
            }
        }
    }

    private fun showIdleState() {
        binding.groupScanning.visibility = View.GONE
        binding.groupError.visibility = View.GONE
        binding.groupIdle.visibility = View.VISIBLE
        binding.animScan.playAnimation()
    }

    private fun showScanningState() {
        binding.groupIdle.visibility = View.GONE
        binding.groupError.visibility = View.GONE
        binding.groupScanning.visibility = View.VISIBLE
        binding.animProcessing.playAnimation()
    }

    private fun showSuccessState(report: FullReport) {
        binding.groupScanning.visibility = View.GONE
        binding.groupError.visibility = View.GONE
        binding.groupIdle.visibility = View.VISIBLE

        // Brief success indicator then navigate
        val intent = Intent(this, CardDetailsActivity::class.java).apply {
            putExtra(CardDetailsActivity.EXTRA_UID, report.cardInfo.uid)
            putExtra(CardDetailsActivity.EXTRA_CARD_TYPE, report.cardInfo.cardType.displayName)
            putExtra(CardDetailsActivity.EXTRA_RISK_LEVEL, report.securityReport.overallRiskLevel.label)
            putExtra(CardDetailsActivity.EXTRA_SECURITY_GRADE, report.securityReport.securityGrade.label)
            putExtra(CardDetailsActivity.EXTRA_ENCRYPTION, report.securityReport.encryptionType.displayName)
            putExtra(CardDetailsActivity.EXTRA_MANUFACTURER, report.cardInfo.manufacturer)
            putExtra(CardDetailsActivity.EXTRA_MEMORY, report.cardInfo.memoryCapacity)
            putExtra(CardDetailsActivity.EXTRA_ATQA, report.cardInfo.atqa ?: "N/A")
            putExtra(CardDetailsActivity.EXTRA_SAK, report.cardInfo.sak ?: "N/A")
            putExtra(CardDetailsActivity.EXTRA_REPORT_JSON, com.google.gson.Gson().toJson(report))
        }
        startActivity(intent)
        viewModel.resetState()
    }

    private fun showErrorState(message: String) {
        binding.groupIdle.visibility = View.GONE
        binding.groupScanning.visibility = View.GONE
        binding.groupError.visibility = View.VISIBLE
        binding.tvErrorMessage.text = message
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TAG_DISCOVERED == intent.action ||
            NfcAdapter.ACTION_TECH_DISCOVERED == intent.action ||
            NfcAdapter.ACTION_NDEF_DISCOVERED == intent.action
        ) {
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            tag?.let { viewModel.processNfcTag(it) }
        }
    }
}
