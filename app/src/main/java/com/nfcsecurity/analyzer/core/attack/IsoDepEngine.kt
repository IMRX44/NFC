package com.nfcsecurity.analyzer.core.attack

import android.nfc.Tag
import android.nfc.tech.IsoDep
import javax.inject.Inject
import javax.inject.Singleton

data class ApduResult(
    val command: String,
    val response: ByteArray,
    val responseHex: String,
    val sw1: Int,
    val sw2: Int,
    val statusWord: String,
    val meaning: String,
    val success: Boolean
)

data class DesfireApp(
    val aid: ByteArray,
    val aidHex: String,
    val fileIds: List<Int>
)

@Singleton
class IsoDepEngine @Inject constructor() {

    // SELECT application by AID
    fun selectApplication(tag: Tag, aid: ByteArray): ApduResult {
        val apdu = byteArrayOf(0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            aid.size.toByte()) + aid + byteArrayOf(0x00)
        return sendApdu(tag, apdu, "SELECT AID: ${aid.toHexString()}")
    }

    // GET_VERSION — DESFire specific
    fun desfireGetVersion(tag: Tag): List<ApduResult> {
        val results = mutableListOf<ApduResult>()
        useIsoDep(tag) { isoDep ->
            // Native DESFire command wrapped in ISO 7816
            val cmd1 = byteArrayOf(0x90.toByte(), 0x60.toByte(), 0x00, 0x00, 0x00)
            results.add(sendRaw(isoDep, cmd1, "DESFire GET_VERSION (part 1)"))
            if (results.last().sw1 == 0x91 && results.last().sw2 == 0xAF.toByte().toInt()) {
                val cmd2 = byteArrayOf(0x90.toByte(), 0xAF.toByte(), 0x00, 0x00, 0x00)
                results.add(sendRaw(isoDep, cmd2, "DESFire GET_VERSION (part 2)"))
                results.add(sendRaw(isoDep, cmd2, "DESFire GET_VERSION (part 3)"))
            }
        }
        return results
    }

    // GET_APPLICATION_IDS — list all DESFire AIDs
    fun desfireListApplications(tag: Tag): ApduResult {
        return sendApduNative(tag, byteArrayOf(0x90.toByte(), 0x6A.toByte(), 0x00, 0x00, 0x00),
            "DESFire GET_APPLICATION_IDS")
    }

    // SELECT NDEF application (well-known AID)
    fun selectNdefApplication(tag: Tag): ApduResult {
        val ndefAid = byteArrayOf(0xD2.toByte(), 0x76.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x85.toByte(), 0x01.toByte(), 0x01.toByte())
        return selectApplication(tag, ndefAid)
    }

    // Send custom raw APDU
    fun sendCustomApdu(tag: Tag, apduHex: String): ApduResult {
        val apduBytes = hexStringToByteArray(apduHex)
        return sendApdu(tag, apduBytes, "Custom APDU: $apduHex")
    }

    // Enumerate files in selected DESFire application
    fun desfireGetFileIds(tag: Tag): ApduResult {
        return sendApduNative(tag, byteArrayOf(0x90.toByte(), 0x6F.toByte(), 0x00, 0x00, 0x00),
            "DESFire GET_FILE_IDS")
    }

    // Read a DESFire file
    fun desfireReadFile(tag: Tag, fileNo: Int, offset: Int = 0, length: Int = 0): ApduResult {
        val data = byteArrayOf(
            fileNo.toByte(),
            (offset and 0xFF).toByte(), ((offset shr 8) and 0xFF).toByte(), ((offset shr 16) and 0xFF).toByte(),
            (length and 0xFF).toByte(), ((length shr 8) and 0xFF).toByte(), ((length shr 16) and 0xFF).toByte()
        )
        val apdu = byteArrayOf(0x90.toByte(), 0xBD.toByte(), 0x00, 0x00, data.size.toByte()) + data + byteArrayOf(0x00)
        return sendApduNative(tag, apdu, "DESFire READ_DATA file=$fileNo")
    }

    private fun sendApdu(tag: Tag, apdu: ByteArray, label: String): ApduResult {
        var result = ApduResult("", ByteArray(0), "", 0, 0, "", "", false)
        useIsoDep(tag) { isoDep ->
            result = sendRaw(isoDep, apdu, label)
        }
        return result
    }

    private fun sendApduNative(tag: Tag, apdu: ByteArray, label: String): ApduResult {
        var result = ApduResult("", ByteArray(0), "", 0, 0, "", "", false)
        useIsoDep(tag) { isoDep ->
            result = sendRaw(isoDep, apdu, label)
        }
        return result
    }

    private fun sendRaw(isoDep: IsoDep, apdu: ByteArray, label: String): ApduResult {
        return try {
            val resp = isoDep.transceive(apdu)
            val sw1 = if (resp.size >= 2) resp[resp.size - 2].toInt() and 0xFF else 0
            val sw2 = if (resp.size >= 1) resp[resp.size - 1].toInt() and 0xFF else 0
            val sw = "${"%02X".format(sw1)} ${"%02X".format(sw2)}"
            ApduResult(
                command = label,
                response = resp,
                responseHex = resp.toHexString(),
                sw1 = sw1, sw2 = sw2,
                statusWord = sw,
                meaning = interpretSw(sw1, sw2),
                success = sw1 == 0x90 || sw1 == 0x91
            )
        } catch (e: Exception) {
            ApduResult(label, ByteArray(0), "", 0, 0, "", "Exception: ${e.message}", false)
        }
    }

    private fun interpretSw(sw1: Int, sw2: Int): String = when {
        sw1 == 0x90 && sw2 == 0x00 -> "Success"
        sw1 == 0x91 && sw2 == 0x00 -> "DESFire: OK"
        sw1 == 0x91 && sw2 == 0xAF -> "DESFire: Additional frames available"
        sw1 == 0x91 && sw2 == 0xAE -> "DESFire: Authentication error"
        sw1 == 0x91 && sw2 == 0x40 -> "DESFire: No such key"
        sw1 == 0x91 && sw2 == 0x9D -> "DESFire: Permission denied"
        sw1 == 0x91 && sw2 == 0xA0 -> "DESFire: Application not found"
        sw1 == 0x6A && sw2 == 0x82 -> "File or application not found"
        sw1 == 0x6A && sw2 == 0x86 -> "Incorrect P1/P2"
        sw1 == 0x69 && sw2 == 0x82 -> "Security status not satisfied"
        sw1 == 0x69 && sw2 == 0x85 -> "Conditions of use not satisfied"
        sw1 == 0x6D && sw2 == 0x00 -> "Instruction not supported"
        sw1 == 0x67 && sw2 == 0x00 -> "Wrong length"
        sw1 == 0x61 -> "Response available: $sw2 bytes"
        else -> "SW: ${"%02X".format(sw1)}${"%02X".format(sw2)}"
    }

    private fun useIsoDep(tag: Tag, block: (IsoDep) -> Unit) {
        val isoDep = IsoDep.get(tag) ?: return
        try {
            isoDep.connect()
            isoDep.timeout = 3000
            block(isoDep)
        } finally {
            try { isoDep.close() } catch (_: Exception) {}
        }
    }

    private fun hexStringToByteArray(hex: String): ByteArray {
        val cleaned = hex.replace(" ", "").replace(":", "")
        return ByteArray(cleaned.length / 2) { i ->
            cleaned.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun ByteArray.toHexString() = joinToString(" ") { "%02X".format(it) }
}
