package com.nfcsecurity.analyzer.core.attack

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Generates millions of candidate keys using pattern analysis.
 * Combines dictionary, sequential, XOR-rotated, and manufacturer-specific patterns
 * for much faster real-world key discovery compared to pure random brute-force.
 */
object SmartKeyGenerator {

    // All 6-byte keys we generate are yielded as ByteArray

    fun generateAll(uid: ByteArray? = null): Flow<ByteArray> = flow {
        // 1. Known dictionary keys first (fastest)
        for (key in KeyDictionary.DEFAULT_KEYS) {
            emit(key)
        }

        // 2. UID-derived keys (card-specific, very high hit rate)
        if (uid != null && uid.size >= 4) {
            for (key in uidDerivedKeys(uid)) emit(key)
        }

        // 3. Common byte patterns
        for (key in commonBytePatterns()) emit(key)

        // 4. Sequential nibble variants of known keys
        for (baseKey in KeyDictionary.DEFAULT_KEYS) {
            for (key in nibbleVariants(baseKey)) emit(key)
        }

        // 5. Date-based keys (YYMMDD format common in transit/hotel)
        for (key in dateBasedKeys()) emit(key)

        // 6. Manufacturer-prefix keys
        for (key in manufacturerPrefixKeys()) emit(key)

        // 7. XOR rotations of known keys
        for (baseKey in KeyDictionary.DEFAULT_KEYS) {
            for (key in xorRotations(baseKey)) emit(key)
        }

        // 8. Incremental brute force (last resort) - all 281T is too many,
        //    so we do structured sampling: fix top bytes, vary bottom 3
        for (key in structuredBruteForce()) emit(key)
    }

    private fun uidDerivedKeys(uid: ByteArray): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        val u = uid.take(4).toByteArray()
        // Repeat UID bytes
        keys.add(byteArrayOf(u[0], u[1], u[2], u[3], u[0], u[1]))
        keys.add(byteArrayOf(u[0], u[1], u[2], u[0], u[1], u[2]))
        keys.add(byteArrayOf(u[3], u[2], u[1], u[0], u[3], u[2]))
        // XOR with FF
        keys.add(byteArrayOf(
            (u[0].toInt() xor 0xFF).toByte(),
            (u[1].toInt() xor 0xFF).toByte(),
            (u[2].toInt() xor 0xFF).toByte(),
            (u[3].toInt() xor 0xFF).toByte(),
            u[0], u[1]
        ))
        // Pad UID to 6 bytes
        val padded = ByteArray(6) { if (it < uid.size) uid[it] else 0x00 }
        keys.add(padded)
        return keys
    }

    private fun commonBytePatterns(): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        val singleBytes = listOf(
            0x00, 0xFF, 0xAA, 0x55, 0x0F, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x66, 0x77, 0x88, 0x99, 0xBB, 0xCC, 0xDD, 0xEE,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
        )
        for (b in singleBytes) {
            keys.add(ByteArray(6) { b.toByte() })
        }
        // Alternating patterns
        for (a in listOf(0xA0, 0x5A, 0xF5, 0x0A, 0x50, 0xFA)) {
            for (b in listOf(0x0F, 0xF0, 0xAA, 0x55)) {
                keys.add(byteArrayOf(a.toByte(), b.toByte(), a.toByte(), b.toByte(), a.toByte(), b.toByte()))
            }
        }
        return keys
    }

    private fun nibbleVariants(base: ByteArray): List<ByteArray> {
        if (base.size != 6) return emptyList()
        val keys = mutableListOf<ByteArray>()
        for (pos in 0..5) {
            for (nibble in 0..0xF) {
                val k = base.copyOf()
                k[pos] = ((k[pos].toInt() and 0xF0) or nibble).toByte()
                keys.add(k)
                k[pos] = ((k[pos].toInt() and 0x0F) or (nibble shl 4)).toByte()
                keys.add(k.copyOf())
            }
        }
        return keys
    }

    private fun dateBasedKeys(): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        // Years 2000-2030, months 01-12, days 01-31
        for (year in 0..30) {
            for (month in 1..12) {
                for (day in 1..28 step 7) { // sample days
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

    private fun manufacturerPrefixKeys(): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        // Common manufacturer prefixes used in field deployments
        val prefixes = listOf(
            byteArrayOf(0x04, 0x00, 0x00),
            byteArrayOf(0x04, 0xAE.toByte(), 0x00),
            byteArrayOf(0x04, 0xDA.toByte(), 0x00),
            byteArrayOf(0x02, 0x00, 0x00),
            byteArrayOf(0x49, 0x4E, 0x46),
            byteArrayOf(0x4E, 0x58, 0x50),
            byteArrayOf(0x4E, 0x46, 0x43)
        )
        val suffixes = listOf(
            byteArrayOf(0x00, 0x00, 0x00),
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            byteArrayOf(0x00, 0xFF.toByte(), 0x00),
            byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        )
        for (p in prefixes) {
            for (s in suffixes) {
                keys.add(p + s)
            }
        }
        return keys
    }

    private fun xorRotations(base: ByteArray): List<ByteArray> {
        if (base.size != 6) return emptyList()
        val keys = mutableListOf<ByteArray>()
        val xorMasks = listOf(0xAA, 0x55, 0xFF, 0x0F, 0xF0, 0x11, 0x22, 0x33)
        for (mask in xorMasks) {
            keys.add(ByteArray(6) { (base[it].toInt() xor mask).toByte() })
        }
        // Byte rotations
        for (shift in 1..5) {
            val rotated = ByteArray(6) { base[(it + shift) % 6] }
            keys.add(rotated)
        }
        return keys
    }

    /**
     * Full sequential brute force over all 2^48 combinations.
     * Iterates b0 from 0x00..0xFF, then b1, etc. — complete coverage with no gaps.
     * At ~100 NFC auths/sec this is the long-tail fallback after smart patterns.
     */
    private fun structuredBruteForce(): Sequence<ByteArray> = sequence {
        // Reuse a single array and mutate it — avoids 281T allocations
        val k = ByteArray(6)
        for (b0 in 0..0xFF) {
            k[0] = b0.toByte()
            for (b1 in 0..0xFF) {
                k[1] = b1.toByte()
                for (b2 in 0..0xFF) {
                    k[2] = b2.toByte()
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
    }
}

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    copyInto(result)
    other.copyInto(result, size)
    return result
}
