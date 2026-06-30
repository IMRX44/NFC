package com.nfcsecurity.analyzer.core.attack

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Smart key generator — prioritizes highest-probability keys first.
 * Never generates the full 2^48 space (physically impossible over NFC).
 * Phase 1: dictionary + UID-derived (seconds)
 * Phase 2: smart patterns (minutes)
 * Phase 3: structured partial scan (hours — covers most real-world deployments)
 */
object SmartKeyGenerator {

    fun generateAll(uid: ByteArray? = null): Flow<ByteArray> = flow {
        val seen = HashSet<Long>(65536)

        // Phase 1: Known keys (~40% of real-world cards never changed factory keys)
        for (key in KeyDictionary.DEFAULT_KEYS) {
            val id = key.toLongId()
            if (seen.add(id)) emit(key.copyOf())
        }
        for (key in KnownAppKeys.ALL) {
            val id = key.toLongId()
            if (seen.add(id)) emit(key.copyOf())
        }

        // Phase 2: UID-derived (high hit rate on OEM systems)
        if (uid != null && uid.size >= 4) {
            for (key in uidDerivedKeys(uid)) {
                val id = key.toLongId()
                if (seen.add(id)) emit(key)
            }
        }

        // Phase 3: Common byte patterns (single-byte repeat, alternating)
        for (key in commonBytePatterns()) {
            val id = key.toLongId()
            if (seen.add(id)) emit(key)
        }

        // Phase 4: Nibble variants of every known key
        for (base in KeyDictionary.DEFAULT_KEYS + KnownAppKeys.ALL) {
            for (key in nibbleVariants(base)) {
                val id = key.toLongId()
                if (seen.add(id)) emit(key)
            }
        }

        // Phase 5: XOR rotations of known keys
        val xorMasks = intArrayOf(0xAA, 0x55, 0xFF, 0x0F, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x66, 0x77, 0x88, 0x99, 0xBB, 0xCC, 0xDD, 0xEE)
        for (base in KeyDictionary.DEFAULT_KEYS + KnownAppKeys.ALL) {
            for (mask in xorMasks) {
                val key = ByteArray(6) { (base[it].toInt() xor mask).toByte() }
                val id = key.toLongId()
                if (seen.add(id)) emit(key)
            }
            for (shift in 1..5) {
                val key = ByteArray(6) { base[(it + shift) % 6] }
                val id = key.toLongId()
                if (seen.add(id)) emit(key)
            }
        }

        // Phase 6: Date-based keys
        for (key in dateBasedKeys()) {
            val id = key.toLongId()
            if (seen.add(id)) emit(key)
        }

        // Phase 7: Manufacturer prefix keys
        for (key in manufacturerPrefixKeys()) {
            val id = key.toLongId()
            if (seen.add(id)) emit(key)
        }

        // Phase 8: Structured partial brute force
        for (key in structuredPartialBrute()) {
            val id = key.toLongId()
            if (seen.add(id)) emit(key)
        }
    }

    private fun ByteArray.toLongId(): Long =
        fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }

    // ── UID-derived key algorithms used by real deployments ──────────

    private fun uidDerivedKeys(uid: ByteArray): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        val u = ByteArray(7) { if (it < uid.size) uid[it] else 0x00 }

        keys.add(byteArrayOf(u[0], u[1], u[2], u[3], u[0], u[1]))
        keys.add(byteArrayOf(u[0], u[1], u[2], u[0], u[1], u[2]))
        keys.add(byteArrayOf(u[3], u[2], u[1], u[0], u[3], u[2]))
        keys.add(byteArrayOf(u[0], u[1], u[2], u[3], u[4], u[5]))
        keys.add(byteArrayOf(u[1], u[2], u[3], u[4], u[5], u[6]))
        keys.add(byteArrayOf(u[5], u[4], u[3], u[2], u[1], u[0]))
        for (mask in listOf(0xFF, 0xAA, 0x55, 0x0F, 0xF0, 0x3C, 0xC3, 0x69, 0x96)) {
            keys.add(ByteArray(6) { i -> (u[i % 4].toInt() xor mask).toByte() })
        }
        for (c in listOf(0x00, 0xFF, 0x01, 0x10, 0xA0, 0x0A, 0x5A, 0x12, 0x34)) {
            keys.add(ByteArray(6) { i -> if (i < 4) u[i] else c.toByte() })
        }
        keys.add(ByteArray(6) { i -> ((u[i % 4].toInt() + 1) and 0xFF).toByte() })
        keys.add(ByteArray(6) { i -> ((u[i % 4].toInt() - 1) and 0xFF).toByte() })
        keys.add(ByteArray(6) { i -> ((u[i % 4].toInt() + i) and 0xFF).toByte() })
        keys.add(byteArrayOf(u[0], 0xFF.toByte(), u[1], 0xFF.toByte(), u[2], 0xFF.toByte()))
        keys.add(byteArrayOf(0xFF.toByte(), u[0], 0xFF.toByte(), u[1], 0xFF.toByte(), u[2]))
        val rot = byteArrayOf(u[1], u[2], u[3], u[0], u[1], u[2])
        for (mask in listOf(0x3C, 0xC3, 0x69, 0x5A)) {
            keys.add(ByteArray(6) { i -> (rot[i].toInt() xor mask).toByte() })
        }
        val xorAll = (0 until 4).fold(0) { acc, i -> acc xor u[i].toInt() }
        keys.add(ByteArray(6) { i -> if (i < 4) u[i] else xorAll.toByte() })
        keys.add(uid.copyOf(6).apply { for (i in uid.size until 6) this[i] = 0x00 })
        keys.add(uid.copyOf(6).apply { for (i in uid.size until 6) this[i] = 0xFF.toByte() })
        return keys
    }

    // ── Common byte patterns ─────────────────────────────────────────

    private fun commonBytePatterns(): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        for (b in 0..0xFF) keys.add(ByteArray(6) { b.toByte() })
        val alt = listOf(0xA0, 0x0A, 0x5A, 0xF5, 0xAF, 0xFA, 0x50, 0x05)
        for (a in alt) for (b in alt) if (a != b) {
            keys.add(byteArrayOf(a.toByte(), b.toByte(), a.toByte(), b.toByte(), a.toByte(), b.toByte()))
            keys.add(byteArrayOf(b.toByte(), a.toByte(), b.toByte(), a.toByte(), b.toByte(), a.toByte()))
        }
        for (start in 0..0xFA) {
            keys.add(ByteArray(6) { i -> (start + i).toByte() })
            keys.add(ByteArray(6) { i -> (start + i * 2).toByte() })
        }
        return keys
    }

    // ── Nibble variants ──────────────────────────────────────────────

    private fun nibbleVariants(base: ByteArray): List<ByteArray> {
        if (base.size != 6) return emptyList()
        val keys = mutableListOf<ByteArray>()
        for (pos in 0..5) {
            for (nibble in 0..0xF) {
                val k = base.copyOf()
                k[pos] = ((k[pos].toInt() and 0xF0) or nibble).toByte()
                keys.add(k.copyOf())
                k[pos] = ((base[pos].toInt() and 0x0F) or (nibble shl 4)).toByte()
                keys.add(k.copyOf())
            }
        }
        return keys
    }

    // ── Date-based keys ──────────────────────────────────────────────

    private fun dateBasedKeys(): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        for (year in 0..30) {
            for (month in 1..12) {
                for (day in listOf(1, 7, 14, 21, 28)) {
                    val yy = year.toByte()
                    val mm = month.toByte()
                    val dd = day.toByte()
                    keys.add(byteArrayOf(yy, mm, dd, yy, mm, dd))
                    keys.add(byteArrayOf(dd, mm, yy, dd, mm, yy))
                    keys.add(byteArrayOf(0x20, yy, mm, dd, 0x00, 0x00))
                }
            }
        }
        return keys
    }

    // ── Manufacturer prefix keys ─────────────────────────────────────

    private fun manufacturerPrefixKeys(): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        val prefixes = listOf(
            byteArrayOf(0x04, 0x00, 0x00), byteArrayOf(0x04, 0xAE.toByte(), 0x00),
            byteArrayOf(0x04, 0xDA.toByte(), 0x00), byteArrayOf(0x02, 0x00, 0x00),
            byteArrayOf(0x49, 0x4E, 0x46), byteArrayOf(0x4E, 0x58, 0x50),
            byteArrayOf(0x4E, 0x46, 0x43), byteArrayOf(0x48, 0x49, 0x44),
            byteArrayOf(0x01, 0x02, 0x03), byteArrayOf(0x10, 0x20, 0x30),
        )
        val suffixes = listOf(
            byteArrayOf(0x00, 0x00, 0x00), byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            byteArrayOf(0x00, 0xFF.toByte(), 0x00), byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()),
            byteArrayOf(0x01, 0x02, 0x03), byteArrayOf(0x10, 0x20, 0x30),
        )
        for (p in prefixes) for (s in suffixes) keys.add(p + s)
        return keys
    }

    // ── Structured partial brute force ───────────────────────────────

    private fun structuredPartialBrute(): Sequence<ByteArray> = sequence {
        val topBytes = listOf(
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            byteArrayOf(0x00, 0x00, 0x00),
            byteArrayOf(0xA0.toByte(), 0xA1.toByte(), 0xA2.toByte()),
            byteArrayOf(0xB0.toByte(), 0xB1.toByte(), 0xB2.toByte()),
            byteArrayOf(0xD3.toByte(), 0xF7.toByte(), 0xD3.toByte()),
            byteArrayOf(0x4D.toByte(), 0x3A.toByte(), 0x99.toByte()),
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte()),
            byteArrayOf(0x11, 0x22, 0x33), byteArrayOf(0x44, 0x55, 0x66),
            byteArrayOf(0x77, 0x88.toByte(), 0x99.toByte()),
            byteArrayOf(0x01, 0x02, 0x03), byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()),
            byteArrayOf(0x12, 0x34, 0x56), byteArrayOf(0xFE.toByte(), 0xDC.toByte(), 0xBA.toByte()),
            byteArrayOf(0x10, 0x20, 0x30), byteArrayOf(0x0A, 0x0B, 0x0C),
        )
        val k = ByteArray(6)
        for (top in topBytes) {
            k[0] = top[0]; k[1] = top[1]; k[2] = top[2]
            for (b3 in 0..0xFF) {
                k[3] = b3.toByte()
                for (b4 in 0..0xFF) {
                    k[4] = b4.toByte()
                    for (b5 in 0..0xFF) {
                        k[5] = b5.toByte()
                        yield(k.copyOf())
                    }
                }
            }
        }
    }
}

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    copyInto(result)
    other.copyInto(result, size)
    return result
}
