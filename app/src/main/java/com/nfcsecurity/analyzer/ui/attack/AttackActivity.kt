package com.nfcsecurity.analyzer.ui.attack

import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.databinding.ActivityAttackBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class AttackActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_CARD_TYPE = "extra_card_type"
        const val EXTRA_UID = "extra_uid"
    }

    private lateinit var binding: ActivityAttackBinding
    private val viewModel: AttackViewModel by viewModels()
    private var nfcAdapter: NfcAdapter? = null
    private lateinit var pendingIntent: PendingIntent
    private var currentTag: Tag? = null
    private var activeOperation: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAttackBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Active Testing"

        val cardType = intent.getStringExtra(EXTRA_CARD_TYPE) ?: "Unknown"
        binding.tvCardTypeLabel.text = "Target: $cardType"

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )

        setupTabs(cardType)
        observeViewModel()
        showWaitingForCard()
    }

    private fun setupTabs(cardType: String) {
        val isMifare = cardType.contains("MIFARE Classic", ignoreCase = true)
        val isUltralight = cardType.contains("Ultralight", ignoreCase = true)
        val isDesfire = cardType.contains("DESFire", ignoreCase = true) ||
                cardType.contains("ISO14443", ignoreCase = true)

        // MIFARE Classic operations
        if (isMifare || cardType == "Unknown") {
            setupMifareButtons()
        }
        // Ultralight operations
        if (isUltralight || cardType == "Unknown") {
            setupUltralightButtons()
        }
        // NDEF operations
        setupNdefButtons()
        // ISO-DEP / DESFire operations
        if (isDesfire || cardType == "Unknown") {
            setupIsoDepButtons()
        }
    }

    private fun setupMifareButtons() {
        binding.groupMifare.visibility = View.VISIBLE

        binding.btnDefaultKeyAttack.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            activeOperation = "key_attack"
            confirmAndRun("Run Default Key Dictionary Attack?",
                "This will try ${30} known default keys against all sectors. " +
                        "This is a READ OPERATION — no data is modified.") {
                viewModel.runDefaultKeyAttack(tag)
            }
        }

        binding.btnDumpCard.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            activeOperation = "dump"
            confirmAndRun("Dump Card?",
                "Read all accessible sectors using discovered keys. Read-only operation.") {
                viewModel.dumpCard(tag)
            }
        }

        binding.btnWriteBlock.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showWriteBlockDialog(tag)
        }

        binding.btnValueIncrement.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showValueOpDialog(tag, increment = true)
        }

        binding.btnValueDecrement.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showValueOpDialog(tag, increment = false)
        }
    }

    private fun setupUltralightButtons() {
        binding.groupUltralight.visibility = View.VISIBLE

        binding.btnUlDump.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            confirmAndRun("Dump Ultralight Pages?", "Read all pages including config/lock pages.") {
                viewModel.dumpUltralight(tag)
            }
        }

        binding.btnUlWritePage.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showUlWritePageDialog(tag)
        }
    }

    private fun setupNdefButtons() {
        binding.groupNdef.visibility = View.VISIBLE

        binding.btnNdefWriteUrl.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showInputDialog("Write URL to NDEF", "URL (e.g. https://example.com)") { url ->
                confirmAndRun("Write URL to tag?", "This will OVERWRITE the NDEF content.") {
                    viewModel.writeNdefUrl(tag, url)
                }
            }
        }

        binding.btnNdefWriteText.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showInputDialog("Write Text to NDEF", "Text content") { text ->
                confirmAndRun("Write text to tag?", "This will OVERWRITE the NDEF content.") {
                    viewModel.writeNdefText(tag, text)
                }
            }
        }

        binding.btnNdefWriteSmartPoster.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showSmartPosterDialog(tag)
        }

        binding.btnNdefErase.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            confirmAndRun("Erase NDEF?", "This will ERASE the NDEF message on the tag.") {
                viewModel.eraseNdef(tag)
            }
        }

        binding.btnNdefLock.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            confirmAndRun("LOCK tag as read-only?",
                "⚠ WARNING: This is IRREVERSIBLE. The tag will become permanently read-only.") {
                viewModel.lockTag(tag)
            }
        }
    }

    private fun setupIsoDepButtons() {
        binding.groupIsoDep.visibility = View.VISIBLE

        binding.btnDesfireInfo.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            confirmAndRun("Query DESFire Info?", "Send GET_VERSION and GET_APPLICATION_IDS commands.") {
                viewModel.getDesfireInfo(tag)
            }
        }

        binding.btnCustomApdu.setOnClickListener {
            val tag = currentTag ?: return@setOnClickListener showNoCard()
            showInputDialog("Send Custom APDU", "APDU hex (e.g. 00A4040007D276000085010100)") { apdu ->
                viewModel.sendApdu(tag, apdu)
            }
        }
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            viewModel.state.collect { state ->
                when (state) {
                    is AttackUiState.Idle -> {
                        binding.progressBar.visibility = View.GONE
                    }
                    is AttackUiState.Running -> {
                        binding.progressBar.visibility = View.VISIBLE
                        binding.progressBar.isIndeterminate = true
                    }
                    is AttackUiState.Progress -> {
                        binding.progressBar.visibility = View.VISIBLE
                        binding.progressBar.isIndeterminate = false
                        binding.progressBar.progress = state.percent
                        binding.tvLog.text = state.log
                        scrollLogToBottom()
                    }
                    is AttackUiState.Done -> {
                        binding.progressBar.visibility = View.GONE
                        binding.tvLog.text = state.result
                        scrollLogToBottom()
                    }
                    is AttackUiState.Error -> {
                        binding.progressBar.visibility = View.GONE
                        binding.tvLog.text = "ERROR: ${state.message}"
                    }
                }
            }
        }
    }

    private fun showWaitingForCard() {
        binding.tvLog.text = "Hold NFC card near device to begin active testing.\n\n" +
                "Available operations will appear based on card type."
    }

    private fun showNoCard() {
        Toast.makeText(this, "Hold card near device first", Toast.LENGTH_SHORT).show()
    }

    private fun confirmAndRun(title: String, message: String, action: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Proceed") { _, _ -> action() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showInputDialog(title: String, hint: String, callback: (String) -> Unit) {
        val input = android.widget.EditText(this).apply {
            this.hint = hint
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val value = input.text.toString().trim()
                if (value.isNotEmpty()) callback(value)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showWriteBlockDialog(tag: Tag) {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 16, 48, 16)
        }
        val etSector = android.widget.EditText(this).apply { hint = "Sector (0-15)" }
        val etBlock = android.widget.EditText(this).apply { hint = "Block (absolute)" }
        val etData = android.widget.EditText(this).apply { hint = "16-byte data (hex, 32 chars)" }
        val etKey = android.widget.EditText(this).apply { hint = "Key hex (12 chars)" }
        val cbKeyA = android.widget.CheckBox(this).apply { text = "Use Key A (uncheck for Key B)" ; isChecked = true }
        layout.addView(etSector)
        layout.addView(etBlock)
        layout.addView(etData)
        layout.addView(etKey)
        layout.addView(cbKeyA)

        AlertDialog.Builder(this)
            .setTitle("Write Block")
            .setMessage("⚠ This WRITES data to the card. Ensure authorization.")
            .setView(layout)
            .setPositiveButton("Write") { _, _ ->
                val sector = etSector.text.toString().toIntOrNull() ?: return@setPositiveButton
                val block = etBlock.text.toString().toIntOrNull() ?: return@setPositiveButton
                val data = etData.text.toString()
                val key = etKey.text.toString()
                viewModel.writeBlock(tag, sector, block, data, key, cbKeyA.isChecked)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showUlWritePageDialog(tag: Tag) {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 16, 48, 16)
        }
        val etPage = android.widget.EditText(this).apply { hint = "Page number (≥4)" }
        val etData = android.widget.EditText(this).apply { hint = "4-byte data (hex, 8 chars)" }
        layout.addView(etPage)
        layout.addView(etData)

        AlertDialog.Builder(this)
            .setTitle("Write Ultralight Page")
            .setMessage("⚠ This WRITES data to the card.")
            .setView(layout)
            .setPositiveButton("Write") { _, _ ->
                val page = etPage.text.toString().toIntOrNull() ?: return@setPositiveButton
                val data = etData.text.toString()
                viewModel.writeUltralightPage(tag, page, data)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showValueOpDialog(tag: Tag, increment: Boolean) {
        val title = if (increment) "Increment Value Block" else "Decrement Value Block"
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 16, 48, 16)
        }
        val etSector = android.widget.EditText(this).apply { hint = "Sector" }
        val etBlock = android.widget.EditText(this).apply { hint = "Block" }
        val etKey = android.widget.EditText(this).apply { hint = "Key A (hex)" }
        val etAmount = android.widget.EditText(this).apply { hint = "Amount" }
        layout.addView(etSector); layout.addView(etBlock)
        layout.addView(etKey); layout.addView(etAmount)

        AlertDialog.Builder(this)
            .setTitle(title)
            .setView(layout)
            .setPositiveButton(if (increment) "Increment" else "Decrement") { _, _ ->
                val sector = etSector.text.toString().toIntOrNull() ?: return@setPositiveButton
                val block = etBlock.text.toString().toIntOrNull() ?: return@setPositiveButton
                val key = etKey.text.toString()
                val amount = etAmount.text.toString().toIntOrNull() ?: return@setPositiveButton
                if (increment) viewModel.valueIncrement(tag, sector, block, key, amount)
                else viewModel.valueDecrement(tag, sector, block, key, amount)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showSmartPosterDialog(tag: Tag) {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 16, 48, 16)
        }
        val etUrl = android.widget.EditText(this).apply { hint = "URL" }
        val etTitle = android.widget.EditText(this).apply { hint = "Title" }
        layout.addView(etUrl); layout.addView(etTitle)
        AlertDialog.Builder(this)
            .setTitle("Write Smart Poster")
            .setView(layout)
            .setPositiveButton("Write") { _, _ ->
                val url = etUrl.text.toString()
                val title = etTitle.text.toString()
                viewModel.writeNdefSmartPoster(tag, url, title)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun scrollLogToBottom() {
        binding.scrollLog.post { binding.scrollLog.fullScroll(View.FOCUS_DOWN) }
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
            NfcAdapter.ACTION_TECH_DISCOVERED == intent.action
        ) {
            currentTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            binding.tvLog.text = "✓ Card detected — ready\n\n${binding.tvLog.text}"
            Toast.makeText(this, "Card detected", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}
