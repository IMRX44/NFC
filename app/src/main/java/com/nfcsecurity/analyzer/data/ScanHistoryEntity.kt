package com.nfcsecurity.analyzer.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val uid: String,
    val cardType: String,
    val manufacturer: String,
    val overallRisk: String,
    val securityGrade: String,
    val encryptionType: String,
    val reportJson: String,
    val scannedAt: Long = System.currentTimeMillis()
)
