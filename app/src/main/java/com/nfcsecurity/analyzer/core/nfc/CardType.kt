package com.nfcsecurity.analyzer.core.nfc

enum class CardType(val displayName: String, val protocol: String) {
    MIFARE_CLASSIC("MIFARE Classic", "ISO 14443-3A"),
    MIFARE_ULTRALIGHT("MIFARE Ultralight", "ISO 14443-3A"),
    MIFARE_ULTRALIGHT_C("MIFARE Ultralight C", "ISO 14443-3A"),
    MIFARE_DESFIRE("MIFARE DESFire", "ISO 14443-4A"),
    MIFARE_DESFIRE_EV1("MIFARE DESFire EV1", "ISO 14443-4A"),
    MIFARE_DESFIRE_EV2("MIFARE DESFire EV2", "ISO 14443-4A"),
    MIFARE_DESFIRE_EV3("MIFARE DESFire EV3", "ISO 14443-4A"),
    NTAG213("NTAG213", "ISO 14443-3A"),
    NTAG215("NTAG215", "ISO 14443-3A"),
    NTAG216("NTAG216", "ISO 14443-3A"),
    FELICA("FeliCa", "ISO 18092"),
    ISO14443_A("ISO 14443-A", "ISO 14443-3A"),
    ISO14443_B("ISO 14443-B", "ISO 14443-3B"),
    UNKNOWN("Unknown", "Unknown")
}

enum class EncryptionType(val displayName: String) {
    NONE("No Encryption"),
    DES("DES"),
    TRIPLE_DES("3DES"),
    AES_128("AES-128"),
    AES_192("AES-192"),
    AES_256("AES-256")
}

enum class SecurityGrade(val label: String, val colorRes: Int) {
    LOW("Low Security", android.R.color.holo_red_light),
    MEDIUM("Medium Security", android.R.color.holo_orange_light),
    HIGH("High Security", android.R.color.holo_green_light)
}

enum class RiskLevel(val label: String) {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    CRITICAL("Critical")
}
