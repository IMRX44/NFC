package com.nfcsecurity.analyzer.data

import com.google.gson.Gson
import com.nfcsecurity.analyzer.core.nfc.CardInfo
import com.nfcsecurity.analyzer.core.nfc.NfcCardReader
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.core.report.ReportGenerator
import com.nfcsecurity.analyzer.core.security.SecurityAnalyzer
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
    private val dao: ScanHistoryDao,
    private val securityAnalyzer: SecurityAnalyzer,
    private val reportGenerator: ReportGenerator,
    private val gson: Gson
) {
    val allScans: Flow<List<ScanHistoryEntity>> = dao.getAllScans()

    suspend fun saveReport(report: FullReport): Long {
        val entity = ScanHistoryEntity(
            uid = report.cardInfo.uid,
            cardType = report.cardInfo.cardType.displayName,
            manufacturer = report.cardInfo.manufacturer,
            overallRisk = report.securityReport.overallRiskLevel.label,
            securityGrade = report.securityReport.securityGrade.label,
            encryptionType = report.securityReport.encryptionType.displayName,
            reportJson = gson.toJson(report),
            scannedAt = System.currentTimeMillis()
        )
        return dao.insert(entity)
    }

    fun analyzeCard(cardInfo: CardInfo): FullReport {
        val secReport = securityAnalyzer.analyze(cardInfo)
        return reportGenerator.buildFullReport(cardInfo, secReport)
    }

    suspend fun deleteAll() = dao.deleteAll()
    suspend fun delete(entity: ScanHistoryEntity) = dao.delete(entity)
}
