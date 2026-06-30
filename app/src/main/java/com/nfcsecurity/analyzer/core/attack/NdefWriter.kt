package com.nfcsecurity.analyzer.core.attack

import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import android.nfc.tech.MifareUltralight
import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton

sealed class NdefWriteResult {
    object Success : NdefWriteResult()
    data class Error(val message: String) : NdefWriteResult()
    object ReadOnly : NdefWriteResult()
    data class TooLarge(val maxSize: Int, val payloadSize: Int) : NdefWriteResult()
}

@Singleton
class NdefWriter @Inject constructor() {

    fun writeUrl(tag: Tag, url: String): NdefWriteResult {
        val record = NdefRecord.createUri(URI.create(url))
        return writeMessage(tag, NdefMessage(arrayOf(record)))
    }

    fun writeText(tag: Tag, text: String, locale: String = "en"): NdefWriteResult {
        val record = NdefRecord.createTextRecord(locale, text)
        return writeMessage(tag, NdefMessage(arrayOf(record)))
    }

    fun writeSmartPoster(tag: Tag, url: String, title: String): NdefWriteResult {
        val urlRecord = NdefRecord.createUri(URI.create(url))
        val titleRecord = NdefRecord.createTextRecord("en", title)
        val spPayload = NdefMessage(arrayOf(urlRecord, titleRecord)).toByteArray()
        val spRecord = NdefRecord(
            NdefRecord.TNF_WELL_KNOWN,
            NdefRecord.RTD_SMART_POSTER,
            ByteArray(0),
            spPayload
        )
        return writeMessage(tag, NdefMessage(arrayOf(spRecord)))
    }

    fun writeRawPayload(tag: Tag, tnf: Short, type: ByteArray, payload: ByteArray): NdefWriteResult {
        val record = NdefRecord(tnf, type, ByteArray(0), payload)
        return writeMessage(tag, NdefMessage(arrayOf(record)))
    }

    fun writeAndLock(tag: Tag, url: String): NdefWriteResult {
        val record = NdefRecord.createUri(URI.create(url))
        val msg = NdefMessage(arrayOf(record))
        val result = writeMessage(tag, msg)
        if (result is NdefWriteResult.Success) {
            lockTag(tag)
        }
        return result
    }

    fun eraseNdef(tag: Tag): NdefWriteResult {
        // Write empty NDEF message (single empty text record)
        val emptyRecord = NdefRecord.createTextRecord("en", "")
        return writeMessage(tag, NdefMessage(arrayOf(emptyRecord)))
    }

    fun lockTag(tag: Tag): Result<Unit> {
        val ndef = Ndef.get(tag) ?: return Result.failure(Exception("No NDEF tech"))
        return try {
            ndef.connect()
            if (ndef.canMakeReadOnly()) {
                ndef.makeReadOnly()
                Result.success(Unit)
            } else {
                Result.failure(Exception("Tag does not support read-only locking"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { ndef.close() } catch (_: Exception) {}
        }
    }

    fun formatAndWrite(tag: Tag, message: NdefMessage): NdefWriteResult {
        val formatable = NdefFormatable.get(tag)
            ?: return NdefWriteResult.Error("Tag is not NDEF formatable")
        return try {
            formatable.connect()
            formatable.format(message)
            NdefWriteResult.Success
        } catch (e: Exception) {
            NdefWriteResult.Error(e.message ?: "Format failed")
        } finally {
            try { formatable.close() } catch (_: Exception) {}
        }
    }

    private fun writeMessage(tag: Tag, message: NdefMessage): NdefWriteResult {
        val ndef = Ndef.get(tag) ?: run {
            // Try formatting first
            return formatAndWrite(tag, message)
        }
        return try {
            ndef.connect()
            if (!ndef.isWritable) return NdefWriteResult.ReadOnly
            val maxSize = ndef.maxSize
            val payloadSize = message.byteArrayLength
            if (payloadSize > maxSize) return NdefWriteResult.TooLarge(maxSize, payloadSize)
            ndef.writeNdefMessage(message)
            NdefWriteResult.Success
        } catch (e: Exception) {
            NdefWriteResult.Error(e.message ?: "Write failed")
        } finally {
            try { ndef.close() } catch (_: Exception) {}
        }
    }
}
