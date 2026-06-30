package com.nfcsecurity.analyzer.core.nfc

import com.nfcsecurity.analyzer.core.security.SecurityReport
import java.util.Date

data class CardInfo(
    val uid: String,
    val uidBytes: ByteArray,
    val cardType: CardType,
    val atqa: String?,
    val sak: String?,
    val manufacturer: String,
    val memoryCapacity: String,
    val technologies: List<String>,
    val ndefRecords: List<NdefRecordInfo>,
    val rawAtqa: ByteArray?,
    val atr: String?,
    val scannedAt: Date = Date()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CardInfo) return false
        return uid == other.uid && cardType == other.cardType
    }
    override fun hashCode(): Int = uid.hashCode()
}

data class NdefRecordInfo(
    val type: NdefType,
    val payload: String,
    val rawPayload: ByteArray,
    val isSuspicious: Boolean,
    val suspiciousReason: String?
)

enum class NdefType { URL, TEXT, SMART_POSTER, MIME, EXTERNAL, UNKNOWN }
