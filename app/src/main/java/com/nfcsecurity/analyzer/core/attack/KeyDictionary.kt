package com.nfcsecurity.analyzer.core.attack

object KeyDictionary {

    // Standard MIFARE Classic default and well-known keys
    val DEFAULT_KEYS: List<ByteArray> = listOf(
        // Factory defaults
        byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
        byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00),

        // NXP transport keys
        byteArrayOf(0xA0.toByte(), 0xA1.toByte(), 0xA2.toByte(), 0xA3.toByte(), 0xA4.toByte(), 0xA5.toByte()),
        byteArrayOf(0xB0.toByte(), 0xB1.toByte(), 0xB2.toByte(), 0xB3.toByte(), 0xB4.toByte(), 0xB5.toByte()),
        byteArrayOf(0xD3.toByte(), 0xF7.toByte(), 0xD3.toByte(), 0xF7.toByte(), 0xD3.toByte(), 0xF7.toByte()),

        // NDEF application keys (NXP AN10609)
        byteArrayOf(0xD3.toByte(), 0xF7.toByte(), 0xD3.toByte(), 0xF7.toByte(), 0xD3.toByte(), 0xF7.toByte()),
        byteArrayOf(0xA0.toByte(), 0xA1.toByte(), 0xA2.toByte(), 0xA3.toByte(), 0xA4.toByte(), 0xA5.toByte()),

        // Transit / access control common keys
        byteArrayOf(0x4D.toByte(), 0x3A.toByte(), 0x99.toByte(), 0xC3.toByte(), 0x51.toByte(), 0xDD.toByte()),
        byteArrayOf(0x1A.toByte(), 0x2B.toByte(), 0x3C.toByte(), 0x4D.toByte(), 0x5E.toByte(), 0x6F.toByte()),
        byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte()),
        byteArrayOf(0x71.toByte(), 0x4C.toByte(), 0x5C.toByte(), 0x88.toByte(), 0x6E.toByte(), 0x97.toByte()),
        byteArrayOf(0x58.toByte(), 0x7E.toByte(), 0xE5.toByte(), 0xF9.toByte(), 0x35.toByte(), 0x0F.toByte()),
        byteArrayOf(0xA0.toByte(), 0x47.toByte(), 0x8C.toByte(), 0xC3.toByte(), 0x90.toByte(), 0x91.toByte()),
        byteArrayOf(0x53.toByte(), 0x3C.toByte(), 0xB6.toByte(), 0xC7.toByte(), 0x23.toByte(), 0xF6.toByte()),
        byteArrayOf(0x8F.toByte(), 0xD0.toByte(), 0xA4.toByte(), 0xF2.toByte(), 0x56.toByte(), 0xE9.toByte()),

        // Parking / hotel / common deployments
        byteArrayOf(0x02.toByte(), 0x47.toByte(), 0x8C.toByte(), 0xC3.toByte(), 0x90.toByte(), 0x91.toByte()),
        byteArrayOf(0x6A.toByte(), 0x19.toByte(), 0x84.toByte(), 0x23.toByte(), 0xFB.toByte(), 0x61.toByte()),
        byteArrayOf(0x0F.toByte(), 0x7D.toByte(), 0x50.toByte(), 0x45.toByte(), 0x84.toByte(), 0x80.toByte()),
        byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte(), 0x12.toByte(), 0x34.toByte(), 0x56.toByte()),
        byteArrayOf(0x12.toByte(), 0x34.toByte(), 0x56.toByte(), 0x78.toByte(), 0x9A.toByte(), 0xBC.toByte()),
        byteArrayOf(0xBC.toByte(), 0x9A.toByte(), 0x78.toByte(), 0x56.toByte(), 0x34.toByte(), 0x12.toByte()),
        byteArrayOf(0x11.toByte(), 0x11.toByte(), 0x11.toByte(), 0x11.toByte(), 0x11.toByte(), 0x11.toByte()),
        byteArrayOf(0x22.toByte(), 0x22.toByte(), 0x22.toByte(), 0x22.toByte(), 0x22.toByte(), 0x22.toByte()),
        byteArrayOf(0x49.toByte(), 0xFA.toByte(), 0xE4.toByte(), 0xE3.toByte(), 0x84.toByte(), 0x9B.toByte()),
        byteArrayOf(0x38.toByte(), 0xFC.toByte(), 0xF3.toByte(), 0x30.toByte(), 0x72.toByte(), 0x28.toByte()),
        byteArrayOf(0x8A.toByte(), 0xD5.toByte(), 0x51.toByte(), 0x7B.toByte(), 0x4B.toByte(), 0x18.toByte()),
        byteArrayOf(0x50.toByte(), 0x9D.toByte(), 0x4E.toByte(), 0xEE.toByte(), 0xEA.toByte(), 0xCE.toByte()),
        byteArrayOf(0x74.toByte(), 0x57.toByte(), 0xB2.toByte(), 0x5E.toByte(), 0xD3.toByte(), 0x4F.toByte()),
        byteArrayOf(0x23.toByte(), 0x5B.toByte(), 0x9D.toByte(), 0x04.toByte(), 0xF5.toByte(), 0x1F.toByte()),
        byteArrayOf(0xFC.toByte(), 0x00.toByte(), 0x01.toByte(), 0x8E.toByte(), 0xD3.toByte(), 0x97.toByte()),
        byteArrayOf(0x4E.toByte(), 0xC7.toByte(), 0x72.toByte(), 0xA8.toByte(), 0xB5.toByte(), 0x2A.toByte()),
    )

    fun keyToHex(key: ByteArray): String = key.joinToString("") { "%02X".format(it) }

    fun hexToKey(hex: String): ByteArray {
        require(hex.length == 12) { "Key must be 12 hex characters" }
        return ByteArray(6) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
}
