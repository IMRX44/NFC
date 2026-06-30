package com.nfcsecurity.analyzer.ui.attack

import android.app.AlertDialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.ViewModelProvider
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.databinding.FragmentAttackBinding
import com.nfcsecurity.analyzer.ui.MainViewModel
import com.nfcsecurity.analyzer.ui.ScanState
import com.nfcsecurity.analyzer.ui.console.ConsoleViewModel
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class AttackFragment : Fragment() {

    private var _binding: FragmentAttackBinding? = null
    private val binding get() = _binding!!
    private val mainViewModel: MainViewModel by activityViewModels()
    private lateinit var attackViewModel: AttackViewModel
    private lateinit var consoleViewModel: ConsoleViewModel

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentAttackBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        attackViewModel = ViewModelProvider(this)[AttackViewModel::class.java]
        consoleViewModel = ViewModelProvider(requireActivity())[ConsoleViewModel::class.java]

        observeViewModel()
        setupClickListeners()
    }

    private fun observeViewModel() {
        mainViewModel.scanState.observe(viewLifecycleOwner) { state ->
            val hasTag = state is ScanState.Success
            binding.llNoTag.visibility = if (hasTag) View.GONE else View.VISIBLE
        }

        attackViewModel.attackState.observe(viewLifecycleOwner) { state ->
            when (state) {
                is AttackUiState.Idle -> {
                    binding.llProgress.visibility = View.GONE
                    binding.tvAttackStatus.text = "IDLE"
                }
                is AttackUiState.Running -> {
                    binding.llProgress.visibility = View.VISIBLE
                    binding.tvAttackStatus.text = "RUNNING"
                    binding.tvProgressLabel.text = state.message
                    binding.progressBar.progress = state.progress
                    binding.tvProgressPct.text = "${state.progress}%"
                    consoleViewModel.log(state.message)
                }
                is AttackUiState.Success -> {
                    binding.llProgress.visibility = View.GONE
                    binding.tvAttackStatus.text = "SUCCESS"
                    consoleViewModel.log("[OK] ${state.result}")
                    toast(state.result)
                }
                is AttackUiState.Error -> {
                    binding.llProgress.visibility = View.GONE
                    binding.tvAttackStatus.text = "ERROR"
                    consoleViewModel.log("[ERR] ${state.error}")
                    toast(state.error)
                }
            }
        }
    }

    private fun setupClickListeners() {
        val tag = getCurrentTag()

        binding.btnDictAttack.setOnClickListener {
            requireTag { t -> attackViewModel.runDictionaryAttack(t) }
        }

        binding.btnBruteforce.setOnClickListener {
            requireTag { t ->
                consoleViewModel.log("[*] Starting SmartBruteForce — pattern + structured mode")
                attackViewModel.runSmartBruteForce(t)
            }
        }

        binding.btnDumpCard.setOnClickListener {
            requireTag { t -> attackViewModel.dumpCard(t) }
        }

        binding.btnDumpUltralight.setOnClickListener {
            requireTag { t -> attackViewModel.dumpUltralight(t) }
        }

        binding.btnWriteUrl.setOnClickListener {
            showInputDialog("Write URL", "Enter URL (e.g. https://example.com)") { url ->
                requireTag { t -> attackViewModel.writeUrl(t, url) }
            }
        }

        binding.btnWriteText.setOnClickListener {
            showInputDialog("Write Text", "Enter text to write") { text ->
                requireTag { t -> attackViewModel.writeText(t, text) }
            }
        }

        binding.btnNdefFuzz.setOnClickListener {
            confirmDestructive("NDEF Fuzzer", "Send 20 malformed NDEF payloads to the tag?") {
                requireTag { t -> attackViewModel.ndefFuzz(t) }
            }
        }

        binding.btnEraseNdef.setOnClickListener {
            confirmDestructive("Erase NDEF", "Erase all NDEF content from tag?") {
                requireTag { t -> attackViewModel.eraseNdef(t) }
            }
        }

        binding.btnWriteBlock.setOnClickListener {
            val blockStr = binding.etBlockNum.text.toString()
            val dataStr = binding.etBlockData.text.toString()
            if (blockStr.isEmpty() || dataStr.isEmpty()) { toast("Enter block and data"); return@setOnClickListener }
            val block = blockStr.toIntOrNull() ?: run { toast("Invalid block number"); return@setOnClickListener }
            confirmDestructive("Write Block $block", "Write ${dataStr.length/2} bytes to block $block?") {
                requireTag { t -> attackViewModel.writeBlock(t, block, dataStr) }
            }
        }

        binding.btnFlipAccess.setOnClickListener {
            confirmDestructive("Flip Access Bits", "Set all sectors to key-A read/write? This may lock you out!") {
                requireTag { t -> attackViewModel.flipAccessBits(t) }
            }
        }

        binding.btnTrailerWipe.setOnClickListener {
            confirmDestructive("Trailer Wipe", "Wipe sector trailers (sets default keys)?") {
                requireTag { t -> attackViewModel.trailerWipe(t) }
            }
        }

        binding.btnValueInc.setOnClickListener {
            requireTag { t -> attackViewModel.valueIncrement(t) }
        }
        binding.btnValueDec.setOnClickListener {
            requireTag { t -> attackViewModel.valueDecrement(t) }
        }
        binding.btnValueOverflow.setOnClickListener {
            confirmDestructive("Value Overflow", "Set value block to MAX (0x7FFFFFFF) to trigger overflow?") {
                requireTag { t -> attackViewModel.valueOverflow(t) }
            }
        }

        binding.btnSendApdu.setOnClickListener {
            val apdu = binding.etApdu.text.toString().replace(" ", "")
            if (apdu.isEmpty()) { toast("Enter APDU hex"); return@setOnClickListener }
            requireTag { t -> attackViewModel.sendApdu(t, apdu) }
        }

        binding.btnDesfireEnum.setOnClickListener {
            requireTag { t -> attackViewModel.desfireEnum(t) }
        }

        binding.btnFullChain.setOnClickListener {
            confirmDestructive("Full Chain Attack", "Run: Key Discovery → Full Dump → Clone Simulation?") {
                requireTag { t ->
                    consoleViewModel.log("[*] Starting full chain attack...")
                    attackViewModel.fullChainAttack(t)
                }
            }
        }

        binding.btnRelayInject.setOnClickListener {
            consoleViewModel.log("[*] Relay Inject: simulates tag presence for 10s")
            requireTag { t -> attackViewModel.relayInject(t) }
        }

        binding.btnCloneUid.setOnClickListener {
            toast("UID cloning requires a magic card (Chinese clone). Tap magic card after dumping source.")
            requireTag { t -> attackViewModel.cloneUid(t) }
        }

        binding.btnLockTag.setOnClickListener {
            confirmDestructive("🔒 LOCK TAG", "This is PERMANENT and IRREVERSIBLE. Lock all OTP bits?") {
                requireTag { t -> attackViewModel.lockTag(t) }
            }
        }

        binding.btnCancel.setOnClickListener {
            attackViewModel.cancelAttack()
        }
    }

    private fun getCurrentTag() = (mainViewModel.scanState.value as? ScanState.Success)
        ?.report?.cardInfo

    private fun requireTag(block: (android.nfc.Tag) -> Unit) {
        val tag = attackViewModel.currentTag
        if (tag == null) {
            toast("No NFC tag connected — scan a tag first")
        } else {
            block(tag)
        }
    }

    private fun showInputDialog(title: String, hint: String, onConfirm: (String) -> Unit) {
        val input = EditText(requireContext()).apply {
            this.hint = hint
            setPadding(48, 24, 48, 24)
        }
        AlertDialog.Builder(requireContext())
            .setTitle(title)
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val text = input.text.toString()
                if (text.isNotEmpty()) onConfirm(text)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun confirmDestructive(title: String, message: String, onConfirm: () -> Unit) {
        AlertDialog.Builder(requireContext())
            .setTitle("⚠ $title")
            .setMessage(message)
            .setPositiveButton("PROCEED") { _, _ -> onConfirm() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun toast(msg: String) {
        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
