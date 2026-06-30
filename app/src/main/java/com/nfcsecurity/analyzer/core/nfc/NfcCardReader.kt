package com.nfcsecurity.analyzer.core.nfc

import android.nfc.Tag
import android.nfc.tech.*
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NfcCardReader @Inject constructor() {

    fun readCard(tag: Tag): CardInfo {
        val uid = tag.id.toHexString()
        val techs = tag.techList.toList()

        var atqa: ByteArray? = null
        var sak: Byte? = null
        var atr: String? = null

        // Extract NfcA parameters (MIFARE / NTAGs)
        if (techs.contains(NfcA::class.java.name)) {
            val nfcA = NfcA.get(tag)
            atqa = nfcA?.atqa
            sak = nfcA?.sak?.toByte()
        }

        // Extract IsoDep ATR
        if (techs.contains(IsoDep::class.java.name)) {
            val isoDep = IsoDep.get(tag)
            atr = isoDep?.historicalBytes?.toHexString()
                ?: isoDep?.hiLayerResponse?.toHexString()
        }

        val cardType = identifyCardType(techs, atqa, sak)
        val manufacturer = identifyManufacturer(uid)
        val memCapacity = getMemoryCapacity(cardType)
        val ndefRecords = readNdefRecords(tag)

        return CardInfo(
            uid = uid,
            uidBytes = tag.id,
            cardType = cardType,
            atqa = atqa?.toHexString(),
            sak = sak?.let { String.format("%02X", it) },
            manufacturer = manufacturer,
            memoryCapacity = memCapacity,
            technologies = techs.map { it.substringAfterLast(".") },
            ndefRecords = ndefRecords,
            rawAtqa = atqa,
            atr = atr
        )
    }

    private fun identifyCardType(techs: List<String>, atqa: ByteArray?, sak: Byte?): CardType {
        return when {
            techs.contains(MifareClassic::class.java.name) -> CardType.MIFARE_CLASSIC
            techs.contains(MifareUltralight::class.java.name) -> {
                val ul = identifyUltralightVariant(atqa, sak)
                ul
            }
            techs.contains(IsoDep::class.java.name) && techs.contains(NfcA::class.java.name) -> {
                identifyDesfireVariant(sak)
            }
            techs.contains(NfcF::class.java.name) -> CardType.FELICA
            techs.contains(NfcB::class.java.name) -> CardType.ISO14443_B
            techs.contains(NfcA::class.java.name) -> {
                identifyNfcAVariant(atqa, sak)
            }
            else -> CardType.UNKNOWN
        }
    }

    private fun identifyUltralightVariant(atqa: ByteArray?, sak: Byte?): CardType {
        // NTAG detection based on ATQA
        atqa?.let {
            val atqaVal = ((it[1].toInt() and 0xFF) shl 8) or (it[0].toInt() and 0xFF)
            if (atqaVal == 0x0044) return CardType.MIFARE_ULTRALIGHT_C
        }
        return CardType.MIFARE_ULTRALIGHT
    }

    private fun identifyDesfireVariant(sak: Byte?): CardType {
        return when (sak?.toInt() and 0xFF) {
            0x20 -> CardType.MIFARE_DESFIRE_EV1
            else -> CardType.MIFARE_DESFIRE
        }
    }

    private fun identifyNfcAVariant(atqa: ByteArray?, sak: Byte?): CardType {
        atqa?.let {
            val atqaVal = ((it[1].toInt() and 0xFF) shl 8) or (it[0].toInt() and 0xFF)
            return when (atqaVal) {
                0x0044 -> CardType.NTAG213
                0x0044 -> CardType.NTAG215
                else -> CardType.ISO14443_A
            }
        }
        return CardType.ISO14443_A
    }

    private fun identifyManufacturer(uid: String): String {
        if (uid.length < 2) return "Unknown"
        return when (uid.substring(0, 2).uppercase()) {
            "04" -> "NXP Semiconductors"
            "02", "98" -> "STMicroelectronics"
            "D2" -> "Infineon Technologies"
            "04" -> "NXP Semiconductors"
            "05" -> "Atmel"
            else -> "Unknown Manufacturer"
        }
    }

    private fun getMemoryCapacity(cardType: CardType): String {
        return when (cardType) {
            CardType.MIFARE_CLASSIC -> "1KB / 4KB"
            CardType.MIFARE_ULTRALIGHT -> "64 bytes"
            CardType.MIFARE_ULTRALIGHT_C -> "192 bytes"
            CardType.MIFARE_DESFIRE,
            CardType.MIFARE_DESFIRE_EV1 -> "2KB / 4KB / 8KB"
            CardType.MIFARE_DESFIRE_EV2 -> "2KB / 4KB / 8KB / 16KB / 32KB"
            CardType.MIFARE_DESFIRE_EV3 -> "2KB - 32KB"
            CardType.NTAG213 -> "144 bytes"
            CardType.NTAG215 -> "504 bytes"
            CardType.NTAG216 -> "888 bytes"
            CardType.FELICA -> "Variable"
            else -> "Unknown"
        }
    }

    private fun readNdefRecords(tag: Tag): List<NdefRecordInfo> {
        val result = mutableListOf<NdefRecordInfo>()
        val ndef = Ndef.get(tag) ?: return result
        return try {
            ndef.connect()
            val msg: NdefMessage = ndef.ndefMessage ?: return result
            for (record in msg.records) {
                result.add(parseNdefRecord(record))
            }
            result
        } catch (e: Exception) {
            result
        } finally {
            try { ndef.close() } catch (_: Exception) {}
        }
    }

    private fun parseNdefRecord(record: NdefRecord): NdefRecordInfo {
        return when (record.tnf) {
            NdefRecord.TNF_WELL_KNOWN -> {
                when {
                    record.type.contentEquals(NdefRecord.RTD_URI) -> {
                        val url = record.toUri()?.toString() ?: record.payload.decodeToString()
                        val suspicious = isSuspiciousUrl(url)
                        NdefRecordInfo(NdefType.URL, url, record.payload, suspicious,
                            if (suspicious) "Suspicious URL pattern detected" else null)
                    }
                    record.type.contentEquals(NdefRecord.RTD_TEXT) -> {
                        val text = parseTextRecord(record.payload)
                        NdefRecordInfo(NdefType.TEXT, text, record.payload, false, null)
                    }
                    record.type.contentEquals(NdefRecord.RTD_SMART_POSTER) -> {
                        NdefRecordInfo(NdefType.SMART_POSTER, "Smart Poster Record",
                            record.payload, false, null)
                    }
                    else -> NdefRecordInfo(NdefType.UNKNOWN, record.payload.toHexString(),
                        record.payload, false, null)
                }
            }
            NdefRecord.TNF_MIME_MEDIA -> {
                val mimeType = String(record.type)
                NdefRecordInfo(NdefType.MIME, "MIME: $mimeType", record.payload, false, null)
            }
            NdefRecord.TNF_EXTERNAL_TYPE -> {
                NdefRecordInfo(NdefType.EXTERNAL, "External Type: ${String(record.type)}",
                    record.payload, false, null)
            }
            else -> NdefRecordInfo(NdefType.UNKNOWN, record.payload.toHexString(),
                record.payload, false, null)
        }
    }

    private fun parseTextRecord(payload: ByteArray): String {
        if (payload.isEmpty()) return ""
        val statusByte = payload[0].toInt() and 0xFF
        val langLen = statusByte and 0x3F
        val isUtf16 = (statusByte and 0x80) != 0
        val textStart = 1 + langLen
        if (textStart >= payload.size) return ""
        val textBytes = payload.copyOfRange(textStart, payload.size)
        return if (isUtf16) String(textBytes, Charsets.UTF_16)
        else String(textBytes, Charsets.UTF_8)
    }

    private fun isSuspiciousUrl(url: String): Boolean {
        val suspiciousPatterns = listOf(
            "bit.ly", "tinyurl", "goo.gl", "t.co",
            "javascript:", "data:", "file://"
        )
        return suspiciousPatterns.any { url.lowercase().contains(it) }
    }
}

fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }
