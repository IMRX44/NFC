package com.nfcsecurity.analyzer.ui

import android.nfc.Tag
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nfcsecurity.analyzer.core.nfc.CardInfo
import com.nfcsecurity.analyzer.core.nfc.NfcCardReader
import com.nfcsecurity.analyzer.core.report.FullReport
import com.nfcsecurity.analyzer.data.ScanHistoryEntity
import com.nfcsecurity.analyzer.data.ScanRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class ScanState {
    object Idle : ScanState()
    object Scanning : ScanState()
    data class Success(val report: FullReport) : ScanState()
    data class Error(val message: String) : ScanState()
}

@HiltViewModel
class MainViewModel @Inject constructor(
    private val cardReader: NfcCardReader,
    private val repository: ScanRepository
) : ViewModel() {

    private val _scanState = MutableLiveData<ScanState>(ScanState.Idle)
    val scanState: LiveData<ScanState> = _scanState

    val scanHistory: StateFlow<List<ScanHistoryEntity>> = repository.allScans
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    fun processNfcTag(tag: Tag) {
        viewModelScope.launch(Dispatchers.IO) {
            _scanState.postValue(ScanState.Scanning)
            try {
                val cardInfo = cardReader.readCard(tag)
                val report = repository.analyzeCard(cardInfo)
                repository.saveReport(report)
                _scanState.postValue(ScanState.Success(report))
            } catch (e: Exception) {
                _scanState.postValue(ScanState.Error(e.message ?: "Failed to read card"))
            }
        }
    }

    fun clearHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            repository.deleteAll()
        }
    }

    fun resetState() {
        _scanState.value = ScanState.Idle
    }
}
