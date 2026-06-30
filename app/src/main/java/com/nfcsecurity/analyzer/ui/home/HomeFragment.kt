package com.nfcsecurity.analyzer.ui.home

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.databinding.FragmentHomeBinding
import com.nfcsecurity.analyzer.ui.MainViewModel
import com.nfcsecurity.analyzer.ui.ScanState

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    private val viewModel: MainViewModel by activityViewModels()

    private var scanCount = 0
    private var attackCount = 0
    private var keysFound = 0

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        startRadarAnimation()
        observeViewModel()
        setupClickListeners()
    }

    private fun observeViewModel() {
        viewModel.scanState.observe(viewLifecycleOwner) { state ->
            when (state) {
                is ScanState.Scanning -> {
                    binding.tvScanLabel.text = "SCANNING..."
                    binding.tvStatusBadge.text = "● SCANNING"
                    binding.tvStatusBadge.setTextColor(requireContext().getColor(R.color.neon_yellow))
                }
                is ScanState.Success -> {
                    scanCount++
                    binding.tvTotalScans.text = scanCount.toString()
                    binding.tvScanLabel.text = "HOLD TAG TO SCAN"
                    binding.tvStatusBadge.text = "● READY"
                    binding.tvStatusBadge.setTextColor(requireContext().getColor(R.color.neon_green))

                    val report = state.report
                    binding.cardLastScan.visibility = View.VISIBLE
                    binding.tvLastCardType.text = report.cardInfo.cardType.displayName
                    binding.tvLastCardUid.text = "UID: ${report.cardInfo.uid}"
                    binding.tvLastCardGrade.text = "Grade: ${report.securityReport.securityGrade.label}"
                    val gradeColor = when (report.securityReport.securityGrade.label) {
                        "A+", "A" -> requireContext().getColor(R.color.neon_green)
                        "B", "C" -> requireContext().getColor(R.color.neon_yellow)
                        else -> requireContext().getColor(R.color.neon_red)
                    }
                    binding.tvLastCardGrade.setTextColor(gradeColor)
                }
                is ScanState.Error -> {
                    binding.tvScanLabel.text = "ERROR — TAP AGAIN"
                    binding.tvStatusBadge.text = "● ERROR"
                    binding.tvStatusBadge.setTextColor(requireContext().getColor(R.color.neon_red))
                }
                else -> {
                    binding.tvScanLabel.text = "HOLD TAG TO SCAN"
                    binding.tvStatusBadge.text = "● READY"
                    binding.tvStatusBadge.setTextColor(requireContext().getColor(R.color.neon_green))
                }
            }
        }

        viewModel.scanHistory.observe(viewLifecycleOwner) { history ->
            binding.tvTotalScans.text = history.size.toString()
        }
    }

    private fun setupClickListeners() {
        val navigateTo = { navId: Int ->
            (requireActivity() as? com.nfcsecurity.analyzer.ui.MainActivity)
                ?.binding?.bottomNav?.selectedItemId = navId
        }
        binding.btnQuickDump.setOnClickListener { navigateTo(R.id.nav_attack) }
        binding.btnQuickAttack.setOnClickListener { navigateTo(R.id.nav_attack) }
        binding.btnQuickHistory.setOnClickListener { navigateTo(R.id.nav_history) }
    }

    private fun startRadarAnimation() {
        // Outer ring pulse
        val outerAnim = ObjectAnimator.ofFloat(binding.ivRadarOuter, "alpha", 0.1f, 0.5f, 0.1f).apply {
            duration = 2000
            repeatCount = ValueAnimator.INFINITE
            interpolator = DecelerateInterpolator()
        }
        // Mid ring pulse (offset)
        val midAnim = ObjectAnimator.ofFloat(binding.ivRadarMid, "alpha", 0.3f, 0.7f, 0.3f).apply {
            duration = 2000
            startDelay = 400
            repeatCount = ValueAnimator.INFINITE
        }
        // Center scale pulse
        val scaleX = ObjectAnimator.ofFloat(binding.ivNfcCenter, "scaleX", 0.9f, 1.1f, 0.9f).apply {
            duration = 1500
            repeatCount = ValueAnimator.INFINITE
        }
        val scaleY = ObjectAnimator.ofFloat(binding.ivNfcCenter, "scaleY", 0.9f, 1.1f, 0.9f).apply {
            duration = 1500
            repeatCount = ValueAnimator.INFINITE
        }
        outerAnim.start()
        midAnim.start()
        scaleX.start()
        scaleY.start()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
