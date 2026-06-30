package com.nfcsecurity.analyzer.core.attack

import android.nfc.Tag
import android.nfc.tech.MifareClassic
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import javax.inject.Inject
import javax.inject.Singleton

data class SectorResult(
    val sectorIndex: Int,
    val keyA: ByteArray?,
    val keyB: ByteArray?,
    val keyAFound: Boolean,
    val keyBFound: Boolean,
    val blocks: List<BlockData>,
    val accessBits: ByteArray?,
    val accessDecoded: AccessConditions?
)

data class BlockData(
    val blockIndex: Int,
    val data: ByteArray,
    val hex: String,
    val ascii: String
)

data class AccessConditions(
    val c1: Int, val c2: Int, val c3: Int,
    val keyAReadable: Boolean,
    val keyBReadable: Boolean,
    val dataReadable: Boolean,
    val dataWritable: Boolean,
    val description: String
)

data class AttackProgress(
    val sector: Int,
    val totalSectors: Int,
    val keyTested: String,
    val keyType: String,
    val found: Boolean,
    val message: String
)

data class DumpResult(
    val sectors: List<SectorResult>,
    val totalSectors: Int,
    val crackedSectors: Int,
    val failedSectors: Int,
    val keysFound: Map<Int, Pair<String?, String?>>,
    val rawDump: String
)

@Singleton
class MifareAttackEngine @Inject constructor() {

    /**
     * Dictionary attack: key-first ordering (test each key against all unsolved sectors).
     * One connection for entire attack. Skips already-solved sectors.
     */
    fun attackWithDictionary(
        tag: Tag,
        customKeys: List<ByteArray> = emptyList(),
        includeDefaults: Boolean = true
    ): Flow<AttackProgress> = flow {

        val mifare = MifareClassic.get(tag) ?: run {
            emit(AttackProgress(0, 0, "", "", false, "Not a MIFARE Classic card"))
            return@flow
        }

        try {
            mifare.connect()
            val totalSectors = mifare.sectorCount
            val keyList = buildKeyList(customKeys, includeDefaults)

            val solvedA = BooleanArray(totalSectors)
            val solvedB = BooleanArray(totalSectors)
            var totalFound = 0

            emit(AttackProgress(0, totalSectors, "", "", false,
                "Dictionary attack: ${keyList.size} keys × $totalSectors sectors"))

            for (key in keyList) {
                val allSolved = (0 until totalSectors).all { solvedA[it] && solvedB[it] }
                if (allSolved) break

                val hexKey = KeyDictionary.keyToHex(key)

                for (sector in 0 until totalSectors) {
                    if (!solvedA[sector]) {
                        val ok = tryAuthenticate(mifare, sector, key, 0)
                        if (ok) {
                            solvedA[sector] = true
                            totalFound++
                            emit(AttackProgress(sector, totalSectors, hexKey, "A", true,
                                "✓ Key A s$sector: $hexKey"))
                        }
                    }
                    if (!solvedB[sector]) {
                        val ok = tryAuthenticate(mifare, sector, key, 1)
                        if (ok) {
                            solvedB[sector] = true
                            totalFound++
                            emit(AttackProgress(sector, totalSectors, hexKey, "B", true,
                                "✓ Key B s$sector: $hexKey"))
                        }
                    }
                }
            }

            val solvedCount = (0 until totalSectors).count { solvedA[it] || solvedB[it] }
            emit(AttackProgress(totalSectors, totalSectors, "", "", false,
                "Dictionary complete: $totalFound keys found, $solvedCount/$totalSectors sectors cracked"))

        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    fun dumpCard(tag: Tag, foundKeys: Map<Int, Pair<ByteArray?, ByteArray?>>): DumpResult {
        val mifare = MifareClassic.get(tag)
            ?: return DumpResult(emptyList(), 0, 0, 0, emptyMap(), "Not a MIFARE Classic card")

        val sectors = mutableListOf<SectorResult>()
        var cracked = 0
        var failed = 0
        val keyMap = mutableMapOf<Int, Pair<String?, String?>>()

        try {
            mifare.connect()
            val totalSectors = mifare.sectorCount

            for (sector in 0 until totalSectors) {
                val (keyA, keyB) = foundKeys[sector] ?: Pair(null, null)
                val blocks = mutableListOf<BlockData>()
                var authenticated = false
                var usedKeyA: ByteArray? = null
                var usedKeyB: ByteArray? = null

                // Try Key A
                if (keyA != null) {
                    if (mifare.authenticateSectorWithKeyA(sector, keyA)) {
                        authenticated = true
                        usedKeyA = keyA
                    }
                }

                // Try Key B if A failed or not available
                if (!authenticated && keyB != null) {
                    if (mifare.authenticateSectorWithKeyB(sector, keyB)) {
                        authenticated = true
                        usedKeyB = keyB
                    }
                }

                var accessBits: ByteArray? = null
                var accessDecoded: AccessConditions? = null

                if (authenticated) {
                    cracked++
                    val firstBlock = mifare.sectorToBlock(sector)
                    val blockCount = mifare.getBlockCountInSector(sector)

                    for (b in 0 until blockCount) {
                        val blockIdx = firstBlock + b
                        val data = try { mifare.readBlock(blockIdx) } catch (_: Exception) { ByteArray(16) }
                        val hex = data.joinToString(" ") { "%02X".format(it) }
                        val ascii = String(data.map { if (it in 32..126) it else '.'.code.toByte() }.toByteArray())

                        // Trailer block — extract access bits
                        if (b == blockCount - 1) {
                            accessBits = data.copyOfRange(6, 10)
                            accessDecoded = decodeAccessBits(accessBits)
                        }

                        blocks.add(BlockData(blockIdx, data, hex, ascii))
                    }
                } else {
                    failed++
                }

                keyMap[sector] = Pair(
                    usedKeyA?.let { KeyDictionary.keyToHex(it) },
                    usedKeyB?.let { KeyDictionary.keyToHex(it) }
                )

                sectors.add(SectorResult(
                    sectorIndex = sector,
                    keyA = usedKeyA,
                    keyB = usedKeyB,
                    keyAFound = usedKeyA != null,
                    keyBFound = usedKeyB != null,
                    blocks = blocks,
                    accessBits = accessBits,
                    accessDecoded = accessDecoded
                ))
            }
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }

        val rawDump = buildRawDump(sectors)

        return DumpResult(
            sectors = sectors,
            totalSectors = sectors.size,
            crackedSectors = cracked,
            failedSectors = failed,
            keysFound = keyMap,
            rawDump = rawDump
        )
    }

    fun writeBlock(
        tag: Tag,
        sector: Int,
        block: Int,
        data: ByteArray,
        key: ByteArray,
        useKeyA: Boolean = true
    ): Result<Unit> {
        require(data.size == 16) { "Block data must be exactly 16 bytes" }
        val mifare = MifareClassic.get(tag) ?: return Result.failure(Exception("Not MIFARE Classic"))

        return try {
            mifare.connect()
            val authed = if (useKeyA) {
                mifare.authenticateSectorWithKeyA(sector, key)
            } else {
                mifare.authenticateSectorWithKeyB(sector, key)
            }
            if (!authed) return Result.failure(Exception("Authentication failed"))
            mifare.writeBlock(block, data)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    fun writeAccessBits(
        tag: Tag,
        sector: Int,
        keyA: ByteArray,
        newKeyA: ByteArray,
        newKeyB: ByteArray,
        accessBits: ByteArray
    ): Result<Unit> {
        require(accessBits.size == 4) { "Access bits must be 4 bytes" }
        val mifare = MifareClassic.get(tag) ?: return Result.failure(Exception("Not MIFARE Classic"))

        return try {
            mifare.connect()
            if (!mifare.authenticateSectorWithKeyA(sector, keyA)) {
                return Result.failure(Exception("Authentication with Key A failed"))
            }
            val trailerBlock = mifare.sectorToBlock(sector) + mifare.getBlockCountInSector(sector) - 1

            // Sector trailer: [Key A (6)] [Access Bits (4)] [Key B (6)]
            val trailer = ByteArray(16)
            newKeyA.copyInto(trailer, 0)
            accessBits.copyInto(trailer, 6)
            newKeyB.copyInto(trailer, 10)

            mifare.writeBlock(trailerBlock, trailer)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    fun valueIncrement(tag: Tag, sector: Int, block: Int, key: ByteArray, amount: Int): Result<Unit> {
        val mifare = MifareClassic.get(tag) ?: return Result.failure(Exception("Not MIFARE Classic"))
        return try {
            mifare.connect()
            if (!mifare.authenticateSectorWithKeyA(sector, key)) {
                return Result.failure(Exception("Authentication failed"))
            }
            mifare.increment(block, amount)
            mifare.transfer(block)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    fun valueDecrement(tag: Tag, sector: Int, block: Int, key: ByteArray, amount: Int): Result<Unit> {
        val mifare = MifareClassic.get(tag) ?: return Result.failure(Exception("Not MIFARE Classic"))
        return try {
            mifare.connect()
            if (!mifare.authenticateSectorWithKeyA(sector, key)) {
                return Result.failure(Exception("Authentication failed"))
            }
            mifare.decrement(block, amount)
            mifare.transfer(block)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    /**
     * Fast brute force: ONE connection for entire run.
     * Tests each key against ALL unsolved sectors (both A+B) before moving on.
     * Emits only on hit or every batchSize failures to reduce overhead.
     * This eliminates the ~30ms connect/close cost per attempt.
     */
    fun fastBruteForce(
        tag: Tag,
        keyFlow: kotlinx.coroutines.flow.Flow<ByteArray>,
        batchSize: Int = 500
    ): Flow<AttackProgress> = flow {

        val mifare = MifareClassic.get(tag) ?: run {
            emit(AttackProgress(0, 0, "", "", false, "Not a MIFARE Classic card"))
            return@flow
        }

        try {
            mifare.connect()
            val totalSectors = mifare.sectorCount

            // Track which sectors still need cracking
            val solvedA = BooleanArray(totalSectors)
            val solvedB = BooleanArray(totalSectors)
            val foundA = arrayOfNulls<ByteArray>(totalSectors)
            val foundB = arrayOfNulls<ByteArray>(totalSectors)

            var tested = 0L
            var totalFound = 0

            emit(AttackProgress(0, totalSectors, "", "", false,
                "FastBruteForce started — single-connection mode"))

            keyFlow.collect { key ->
                // Skip iteration if all sectors solved
                val allSolved = (0 until totalSectors).all { solvedA[it] && solvedB[it] }
                if (allSolved) return@collect

                val hexKey = KeyDictionary.keyToHex(key)
                tested++

                for (sector in 0 until totalSectors) {
                    // Test Key A if not yet found
                    if (!solvedA[sector]) {
                        val ok = tryAuthenticate(mifare, sector, key, 0)
                        if (ok) {
                            solvedA[sector] = true
                            foundA[sector] = key.copyOf()
                            totalFound++
                            emit(AttackProgress(sector, totalSectors, hexKey, "A", true,
                                "✓ KEY A s${sector}: $hexKey  [${tested} tested]"))
                        }
                    }
                    // Test Key B if not yet found
                    if (!solvedB[sector]) {
                        val ok = tryAuthenticate(mifare, sector, key, 1)
                        if (ok) {
                            solvedB[sector] = true
                            foundB[sector] = key.copyOf()
                            totalFound++
                            emit(AttackProgress(sector, totalSectors, hexKey, "B", true,
                                "✓ KEY B s${sector}: $hexKey  [${tested} tested]"))
                        }
                    }
                }

                // Progress heartbeat every batchSize attempts
                if (tested % batchSize == 0L) {
                    val solvedCount = (0 until totalSectors).count { solvedA[it] || solvedB[it] }
                    emit(AttackProgress(solvedCount, totalSectors, hexKey, "", false,
                        "Tested: $tested  Found: $totalFound  Sectors cracked: $solvedCount/$totalSectors"))
                }
            }

            // Build result summary
            val summary = buildString {
                appendLine("FastBruteForce complete: $tested keys tested, $totalFound keys found")
                for (s in 0 until totalSectors) {
                    val a = foundA[s]?.let { KeyDictionary.keyToHex(it) } ?: "NOT FOUND"
                    val b = foundB[s]?.let { KeyDictionary.keyToHex(it) } ?: "NOT FOUND"
                    appendLine("Sector $s → A: $a  B: $b")
                }
            }
            emit(AttackProgress(totalSectors, totalSectors, "", "", false, summary))

        } catch (e: Exception) {
            emit(AttackProgress(0, 0, "", "", false, "Error: ${e.message}"))
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    /** Quick single-key probe (keeps connection open if already connected). */
    fun probeKey(tag: Tag, sector: Int, key: ByteArray, useKeyA: Boolean): Boolean {
        val mifare = MifareClassic.get(tag) ?: return false
        return try {
            if (!mifare.isConnected) mifare.connect()
            if (useKeyA) mifare.authenticateSectorWithKeyA(sector, key)
            else mifare.authenticateSectorWithKeyB(sector, key)
        } catch (_: Exception) {
            false
        } finally {
            try { mifare.close() } catch (_: Exception) {}
        }
    }

    private fun tryAuthenticate(mifare: MifareClassic, sector: Int, key: ByteArray, keyType: Int): Boolean {
        return try {
            if (keyType == 0) {
                mifare.authenticateSectorWithKeyA(sector, key)
            } else {
                mifare.authenticateSectorWithKeyB(sector, key)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun buildKeyList(custom: List<ByteArray>, includeDefaults: Boolean): List<ByteArray> {
        val list = mutableListOf<ByteArray>()
        if (includeDefaults) list.addAll(KeyDictionary.DEFAULT_KEYS)
        list.addAll(custom)
        return list
    }

    private fun decodeAccessBits(raw: ByteArray): AccessConditions {
        if (raw.size < 4) return AccessConditions(0, 0, 0,
            keyAReadable = false, keyBReadable = false,
            dataReadable = true, dataWritable = true,
            description = "Could not parse access bits")

        val b6 = raw[0].toInt() and 0xFF
        val b7 = raw[1].toInt() and 0xFF
        val b8 = raw[2].toInt() and 0xFF

        val c1 = ((b7 shr 4) and 0x0F)
        val c2 = ((b8) and 0x0F)
        val c3 = ((b8 shr 4) and 0x0F)

        // Sector trailer (block 3) access conditions for data block 0
        val c10 = (c1 shr 0) and 1
        val c20 = (c2 shr 0) and 1
        val c30 = (c3 shr 0) and 1

        val desc = when ("$c10$c20$c30") {
            "000" -> "Read/Write with Key A or B (transport config)"
            "010" -> "Read with Key A or B; Write never (read-only)"
            "100" -> "Read with Key A or B; Write with Key B only"
            "110" -> "Read with Key B; Write with Key B (Key A useless)"
            "001" -> "Read with Key A or B; Write/Decrement Key A or B; Increment never"
            "011" -> "Read/Decrement with Key A or B; Write/Increment with Key B"
            "101" -> "Read with Key B; Write/Decrement/Increment with Key B"
            "111" -> "Read with Key A or B; No write (highly restricted)"
            else -> "Unknown access condition"
        }

        return AccessConditions(
            c1 = c1, c2 = c2, c3 = c3,
            keyAReadable = false,
            keyBReadable = (c30 == 1),
            dataReadable = true,
            dataWritable = (c10 == 0 && c20 == 0 && c30 == 0) || (c10 == 1 && c20 == 0 && c30 == 0),
            description = desc
        )
    }

    private fun buildRawDump(sectors: List<SectorResult>): String {
        val sb = StringBuilder()
        sb.appendLine("=== MIFARE Classic Raw Dump ===")
        for (sector in sectors) {
            sb.appendLine("\n--- Sector ${sector.sectorIndex} " +
                    "[Key A: ${sector.keyA?.let { KeyDictionary.keyToHex(it) } ?: "NOT FOUND"} | " +
                    "Key B: ${sector.keyB?.let { KeyDictionary.keyToHex(it) } ?: "NOT FOUND"}] ---")
            if (sector.blocks.isEmpty()) {
                sb.appendLine("  (auth failed — no data)")
            } else {
                for (block in sector.blocks) {
                    sb.appendLine("  Block ${block.blockIndex}: ${block.hex}  |${block.ascii}|")
                }
                sector.accessDecoded?.let {
                    sb.appendLine("  Access: ${it.description}")
                }
            }
        }
        return sb.toString()
    }
}
