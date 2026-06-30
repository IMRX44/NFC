package com.nfcsecurity.analyzer.ui.attack

import android.nfc.Tag
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nfcsecurity.analyzer.core.attack.*
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class AttackUiState {
    object Idle : AttackUiState()
    object Running : AttackUiState()
    data class Progress(val log: String, val percent: Int) : AttackUiState()
    data class Done(val result: String) : AttackUiState()
    data class Error(val message: String) : AttackUiState()
}

@HiltViewModel
class AttackViewModel @Inject constructor(
    private val mifareEngine: MifareAttackEngine,
    private val ndefWriter: NdefWriter,
    private val ultralightEngine: UltralightEngine,
    private val isoDepEngine: IsoDepEngine
) : ViewModel() {

    private val _state = MutableStateFlow<AttackUiState>(AttackUiState.Idle)
    val state: StateFlow<AttackUiState> = _state

    private val _log = MutableLiveData("")
    val log: LiveData<String> = _log

    // Discovered keys: sector -> Pair(keyA, keyB)
    private val foundKeys = mutableMapOf<Int, Pair<ByteArray?, ByteArray?>>()
    private var lastDump: DumpResult? = null

    fun runDefaultKeyAttack(tag: Tag, customKeys: List<ByteArray> = emptyList()) {
        foundKeys.clear()
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val sb = StringBuilder()
            var totalSectors = 0

            mifareEngine.attackWithDictionary(tag, customKeys).collect { progress ->
                totalSectors = maxOf(totalSectors, progress.totalSectors)
                sb.appendLine(progress.message)
                _log.postValue(sb.toString())

                if (progress.found) {
                    val current = foundKeys[progress.sector] ?: Pair(null, null)
                    foundKeys[progress.sector] = if (progress.keyType == "A") {
                        Pair(KeyDictionary.hexToKey(progress.keyTested), current.second)
                    } else {
                        Pair(current.first, KeyDictionary.hexToKey(progress.keyTested))
                    }
                }

                val percent = if (totalSectors > 0)
                    (progress.sector * 100) / totalSectors else 0
                _state.value = AttackUiState.Progress(sb.toString(), percent)
            }

            val summary = buildKeySummary(foundKeys, totalSectors)
            sb.appendLine()
            sb.appendLine(summary)
            _log.postValue(sb.toString())
            _state.value = AttackUiState.Done(sb.toString())
        }
    }

    fun dumpCard(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            _log.postValue("Starting card dump with ${foundKeys.size} known keys…")

            val result = mifareEngine.dumpCard(tag, foundKeys)
            lastDump = result

            val output = buildDumpOutput(result)
            _log.postValue(output)
            _state.value = AttackUiState.Done(output)
        }
    }

    fun writeBlock(tag: Tag, sector: Int, block: Int, hexData: String, hexKey: String, useKeyA: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            try {
                val data = hexToBytes(hexData)
                val key = KeyDictionary.hexToKey(hexKey)
                val result = mifareEngine.writeBlock(tag, sector, block, data, key, useKeyA)
                result.fold(
                    onSuccess = {
                        _log.postValue("✓ Block $block written successfully")
                        _state.value = AttackUiState.Done("Block written OK")
                    },
                    onFailure = {
                        _log.postValue("✗ Write failed: ${it.message}")
                        _state.value = AttackUiState.Error(it.message ?: "Write failed")
                    }
                )
            } catch (e: Exception) {
                _state.value = AttackUiState.Error(e.message ?: "Error")
            }
        }
    }

    fun writeNdefUrl(tag: Tag, url: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val result = ndefWriter.writeUrl(tag, url)
            handleNdefResult(result, "URL write")
        }
    }

    fun writeNdefText(tag: Tag, text: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val result = ndefWriter.writeText(tag, text)
            handleNdefResult(result, "Text write")
        }
    }

    fun writeNdefSmartPoster(tag: Tag, url: String, title: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val result = ndefWriter.writeSmartPoster(tag, url, title)
            handleNdefResult(result, "Smart Poster write")
        }
    }

    fun eraseNdef(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val result = ndefWriter.eraseNdef(tag)
            handleNdefResult(result, "NDEF erase")
        }
    }

    fun lockTag(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            ndefWriter.lockTag(tag).fold(
                onSuccess = {
                    _log.postValue("✓ Tag locked as read-only")
                    _state.value = AttackUiState.Done("Tag locked successfully")
                },
                onFailure = {
                    _log.postValue("✗ Lock failed: ${it.message}")
                    _state.value = AttackUiState.Error(it.message ?: "Lock failed")
                }
            )
        }
    }

    fun dumpUltralight(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            ultralightEngine.dumpAllPages(tag).fold(
                onSuccess = { dump ->
                    val sb = StringBuilder()
                    sb.appendLine("=== ${dump.type} Dump ===")
                    sb.appendLine("Password Protected: ${if (dump.isPasswordProtected) "YES ⚠" else "NO"}")
                    sb.appendLine()
                    sb.appendLine("Config:")
                    sb.appendLine(dump.configPages)
                    sb.appendLine("Pages:")
                    dump.pages.forEach { page ->
                        sb.appendLine("  Page ${"%02d".format(page.pageIndex)}: ${page.hex}  | ${page.description}")
                    }
                    val output = sb.toString()
                    _log.postValue(output)
                    _state.value = AttackUiState.Done(output)
                },
                onFailure = {
                    _state.value = AttackUiState.Error(it.message ?: "Dump failed")
                }
            )
        }
    }

    fun writeUltralightPage(tag: Tag, page: Int, hexData: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            try {
                val data = hexToBytes(hexData)
                ultralightEngine.writePage(tag, page, data).fold(
                    onSuccess = {
                        _log.postValue("✓ Page $page written: $hexData")
                        _state.value = AttackUiState.Done("Page $page written OK")
                    },
                    onFailure = {
                        _state.value = AttackUiState.Error(it.message ?: "Write failed")
                    }
                )
            } catch (e: Exception) {
                _state.value = AttackUiState.Error(e.message ?: "Invalid hex data")
            }
        }
    }

    fun sendApdu(tag: Tag, apduHex: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val result = isoDepEngine.sendCustomApdu(tag, apduHex)
            val output = """
APDU: $apduHex
Response: ${result.responseHex}
Status: ${result.statusWord} — ${result.meaning}
            """.trimIndent()
            _log.postValue(output)
            _state.value = AttackUiState.Done(output)
        }
    }

    fun getDesfireInfo(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            val sb = StringBuilder()

            val apps = isoDepEngine.desfireListApplications(tag)
            sb.appendLine("=== DESFire Application List ===")
            sb.appendLine("Response: ${apps.responseHex}")
            sb.appendLine("Status: ${apps.meaning}")
            sb.appendLine()

            val version = isoDepEngine.desfireGetVersion(tag)
            sb.appendLine("=== DESFire Version Info ===")
            version.forEach { v ->
                sb.appendLine("${v.command}")
                sb.appendLine("  Response: ${v.responseHex}")
                sb.appendLine("  Status: ${v.meaning}")
            }

            _log.postValue(sb.toString())
            _state.value = AttackUiState.Done(sb.toString())
        }
    }

    fun valueIncrement(tag: Tag, sector: Int, block: Int, hexKey: String, amount: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            try {
                val key = KeyDictionary.hexToKey(hexKey)
                mifareEngine.valueIncrement(tag, sector, block, key, amount).fold(
                    onSuccess = {
                        _log.postValue("✓ Block $block incremented by $amount")
                        _state.value = AttackUiState.Done("Value incremented")
                    },
                    onFailure = {
                        _state.value = AttackUiState.Error(it.message ?: "Increment failed")
                    }
                )
            } catch (e: Exception) {
                _state.value = AttackUiState.Error(e.message ?: "Error")
            }
        }
    }

    fun valueDecrement(tag: Tag, sector: Int, block: Int, hexKey: String, amount: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = AttackUiState.Running
            try {
                val key = KeyDictionary.hexToKey(hexKey)
                mifareEngine.valueDecrement(tag, sector, block, key, amount).fold(
                    onSuccess = {
                        _log.postValue("✓ Block $block decremented by $amount")
                        _state.value = AttackUiState.Done("Value decremented")
                    },
                    onFailure = {
                        _state.value = AttackUiState.Error(it.message ?: "Decrement failed")
                    }
                )
            } catch (e: Exception) {
                _state.value = AttackUiState.Error(e.message ?: "Error")
            }
        }
    }

    private fun handleNdefResult(result: NdefWriteResult, label: String) {
        when (result) {
            is NdefWriteResult.Success -> {
                _log.postValue("✓ $label successful")
                _state.value = AttackUiState.Done("$label OK")
            }
            is NdefWriteResult.ReadOnly -> {
                _log.postValue("✗ Tag is read-only, cannot write")
                _state.value = AttackUiState.Error("Tag is read-only")
            }
            is NdefWriteResult.TooLarge -> {
                _log.postValue("✗ Payload too large: ${result.payloadSize} bytes, max ${result.maxSize}")
                _state.value = AttackUiState.Error("Payload too large")
            }
            is NdefWriteResult.Error -> {
                _log.postValue("✗ $label failed: ${result.message}")
                _state.value = AttackUiState.Error(result.message)
            }
        }
    }

    private fun buildKeySummary(keys: Map<Int, Pair<ByteArray?, ByteArray?>>, total: Int): String {
        val sb = StringBuilder()
        sb.appendLine("═══ KEY RECOVERY SUMMARY ═══")
        sb.appendLine("Sectors tested: $total")
        sb.appendLine("Keys found: ${keys.values.count { it.first != null || it.second != null }}")
        sb.appendLine()
        keys.toSortedMap().forEach { (sector, pair) ->
            val a = pair.first?.let { KeyDictionary.keyToHex(it) } ?: "NOT FOUND"
            val b = pair.second?.let { KeyDictionary.keyToHex(it) } ?: "NOT FOUND"
            sb.appendLine("  Sector $sector  Key A: $a | Key B: $b")
        }
        return sb.toString()
    }

    private fun buildDumpOutput(result: DumpResult): String {
        val sb = StringBuilder()
        sb.appendLine("═══ CARD DUMP ═══")
        sb.appendLine("Sectors: ${result.totalSectors} | Cracked: ${result.crackedSectors} | Failed: ${result.failedSectors}")
        sb.appendLine()
        sb.appendLine(result.rawDump)
        return sb.toString()
    }

    private fun hexToBytes(hex: String): ByteArray {
        val cleaned = hex.replace(" ", "").replace(":", "")
        return ByteArray(cleaned.length / 2) { i ->
            cleaned.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun getFoundKeys() = foundKeys.toMap()
    fun getLastDump() = lastDump
}
