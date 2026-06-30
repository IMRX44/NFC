package com.nfcsecurity.analyzer.ui.scan

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.google.gson.Gson
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.core.security.SecurityReport
import com.nfcsecurity.analyzer.databinding.FragmentScanBinding
import com.nfcsecurity.analyzer.ui.MainViewModel
import com.nfcsecurity.analyzer.ui.ScanState
import com.nfcsecurity.analyzer.ui.attack.AttackActivity
import com.nfcsecurity.analyzer.ui.details.CardDetailsActivity
import com.nfcsecurity.analyzer.ui.report.ReportActivity

class ScanFragment : Fragment() {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private val viewModel: MainViewModel by activityViewModels()
    private var currentReport: FullReport? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentScanBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        observeViewModel()
        setupClickListeners()
    }

    private fun observeViewModel() {
        viewModel.scanState.observe(viewLifecycleOwner) { state ->
            when (state) {
                is ScanState.Success -> showScanResult(state.report)
                is ScanState.Scanning -> showLoading()
                else -> {}
            }
        }
    }

    private fun showLoading() {
        binding.llEmpty.visibility = View.GONE
        binding.cardInfoPanel.visibility = View.GONE
    }

    private fun showScanResult(report: FullReport) {
        currentReport = report
        binding.llEmpty.visibility = View.GONE
        binding.cardInfoPanel.visibility = View.VISIBLE
        binding.tvVulnsHeader.visibility = View.VISIBLE
        binding.llActions.visibility = View.VISIBLE

        binding.tvCardType.text = report.cardInfo.cardType.displayName
        binding.tvSecurityGrade.text = report.securityReport.securityGrade.label
        binding.tvUid.text = report.cardInfo.uid
        binding.tvAtqa.text = report.cardInfo.atqa ?: "N/A"
        binding.tvSak.text = report.cardInfo.sak ?: "N/A"
        binding.tvEncryption.text = report.securityReport.encryptionType.displayName
        binding.tvSize.text = "${report.cardInfo.memoryCapacity} bytes"

        val gradeColor = when (report.securityReport.securityGrade.label) {
            "A+", "A" -> requireContext().getColor(R.color.neon_green)
            "B" -> requireContext().getColor(R.color.neon_yellow)
            "C" -> requireContext().getColor(R.color.neon_orange)
            else -> requireContext().getColor(R.color.neon_red)
        }
        binding.tvSecurityGrade.setTextColor(gradeColor)

        // Populate vulnerabilities
        binding.llVulns.removeAllViews()
        for (vuln in report.securityReport.vulnerabilities.take(10)) {
            val itemView = layoutInflater.inflate(R.layout.item_vulnerability, binding.llVulns, false)
            itemView.findViewById<android.widget.TextView>(R.id.tv_vuln_title).text = vuln.title
            itemView.findViewById<android.widget.TextView>(R.id.tv_vuln_desc).text = vuln.description
            itemView.findViewById<android.widget.TextView>(R.id.tv_cvss).text = String.format("%.1f", vuln.cvssScore)
            val color = when {
                vuln.cvssScore >= 9.0 -> requireContext().getColor(R.color.neon_red)
                vuln.cvssScore >= 7.0 -> requireContext().getColor(R.color.neon_orange)
                vuln.cvssScore >= 4.0 -> requireContext().getColor(R.color.neon_yellow)
                else -> requireContext().getColor(R.color.neon_green)
            }
            itemView.findViewById<android.widget.TextView>(R.id.tv_cvss).setTextColor(color)
            itemView.findViewById<View>(R.id.view_severity_bar).setBackgroundColor(color)
            binding.llVulns.addView(itemView)
        }
    }

    private fun setupClickListeners() {
        binding.btnAttackCard.setOnClickListener {
            currentReport?.let { report ->
                val intent = Intent(requireContext(), AttackActivity::class.java).apply {
                    putExtra("card_uid", report.cardInfo.uid)
                    putExtra("card_type", report.cardInfo.cardType.name)
                }
                startActivity(intent)
            }
        }
        binding.btnExportReport.setOnClickListener {
            currentReport?.let { report ->
                val intent = Intent(requireContext(), ReportActivity::class.java).apply {
                    putExtra("report_json", Gson().toJson(report))
                }
                startActivity(intent)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
