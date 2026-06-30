package com.nfcsecurity.analyzer.core.attack

import android.nfc.Tag
import android.nfc.tech.MifareUltralight
import javax.inject.Inject
import javax.inject.Singleton

data class UltralightPage(
    val pageIndex: Int,
    val data: ByteArray,
    val hex: String,
    val description: String
)

data class UltralightDump(
    val pages: List<UltralightPage>,
    val type: String,
    val isPasswordProtected: Boolean,
    val configPages: String
)

@Singleton
class UltralightEngine @Inject constructor() {

    fun dumpAllPages(tag: Tag): Result<UltralightDump> {
        val ul = MifareUltralight.get(tag) ?: return Result.failure(Exception("Not MifareUltralight"))
        return try {
            ul.connect()
            val pages = mutableListOf<UltralightPage>()
            val maxPage = when (ul.type) {
                MifareUltralight.TYPE_ULTRALIGHT -> 16
                MifareUltralight.TYPE_ULTRALIGHT_C -> 48
                else -> 20
            }

            var page = 0
            while (page < maxPage) {
                try {
                    val data = ul.readPages(page)  // reads 4 pages at once
                    for (i in 0 until 4) {
                        if (page + i < maxPage) {
                            val pageData = data.copyOfRange(i * 4, i * 4 + 4)
                            pages.add(UltralightPage(
                                pageIndex = page + i,
                                data = pageData,
                                hex = pageData.joinToString(" ") { "%02X".format(it) },
                                description = describeUltralightPage(page + i, ul.type)
                            ))
                        }
                    }
                    page += 4
                } catch (e: Exception) {
                    // Auth-protected pages will fail
                    for (i in 0 until 4) {
                        if (page + i < maxPage) {
                            pages.add(UltralightPage(
                                pageIndex = page + i,
                                data = ByteArray(4),
                                hex = "?? ?? ?? ??",
                                description = "LOCKED/AUTH REQUIRED"
                            ))
                        }
                    }
                    page += 4
                }
            }

            val isProtected = pages.any { it.description.contains("LOCKED") }

            UltralightDump(
                pages = pages,
                type = when (ul.type) {
                    MifareUltralight.TYPE_ULTRALIGHT -> "MIFARE Ultralight"
                    MifareUltralight.TYPE_ULTRALIGHT_C -> "MIFARE Ultralight C"
                    else -> "Unknown Ultralight"
                },
                isPasswordProtected = isProtected,
                configPages = buildConfigSummary(pages)
            ).let { Result.success(it) }
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { ul.close() } catch (_: Exception) {}
        }
    }

    fun writePage(tag: Tag, page: Int, data: ByteArray): Result<Unit> {
        require(data.size == 4) { "Page data must be 4 bytes" }
        require(page >= 4) { "Cannot write to reserved pages 0-3" }
        val ul = MifareUltralight.get(tag) ?: return Result.failure(Exception("Not MifareUltralight"))
        return try {
            ul.connect()
            ul.writePage(page, data)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { ul.close() } catch (_: Exception) {}
        }
    }

    fun writeOtpBits(tag: Tag, otpData: ByteArray): Result<Unit> {
        require(otpData.size == 4) { "OTP data must be 4 bytes" }
        val ul = MifareUltralight.get(tag) ?: return Result.failure(Exception("Not MifareUltralight"))
        return try {
            ul.connect()
            ul.writePage(3, otpData)  // OTP is page 3
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { ul.close() } catch (_: Exception) {}
        }
    }

    private fun describeUltralightPage(page: Int, type: Int): String = when (page) {
        0 -> "UID bytes 0-2 + check byte BCC0"
        1 -> "UID bytes 3-6"
        2 -> "BCC1 + internal + LOCK0 + LOCK1"
        3 -> "OTP (One-Time-Programmable) bits"
        in 4..39 -> "User data page $page"
        40 -> "CFG0 — Mirror/Auth config"
        41 -> "CFG1 — Password auth config"
        42 -> "PWD — 32-bit password"
        43 -> "PACK — Password acknowledge"
        else -> "Reserved page $page"
    }

    private fun buildConfigSummary(pages: List<UltralightPage>): String {
        val sb = StringBuilder()
        // Lock bytes in page 2
        pages.getOrNull(2)?.let { p ->
            if (p.data.size >= 4) {
                val lock0 = p.data[2].toInt() and 0xFF
                val lock1 = p.data[3].toInt() and 0xFF
                sb.appendLine("Lock bytes: ${"%02X".format(lock0)} ${"%02X".format(lock1)}")
                if (lock0 != 0 || lock1 != 0) {
                    sb.appendLine("  WARNING: Some pages are locked (write-protected)")
                }
            }
        }
        // Config pages (NTAG)
        pages.getOrNull(40)?.let { p ->
            sb.appendLine("CFG0: ${p.hex}")
        }
        pages.getOrNull(41)?.let { p ->
            sb.appendLine("CFG1: ${p.hex}")
            val accessByte = if (p.data.isNotEmpty()) p.data[0].toInt() and 0xFF else 0
            if ((accessByte and 0x80) != 0) sb.appendLine("  Password protection: ENABLED")
            else sb.appendLine("  Password protection: DISABLED")
        }
        return sb.toString().ifEmpty { "Standard configuration" }
    }
}
