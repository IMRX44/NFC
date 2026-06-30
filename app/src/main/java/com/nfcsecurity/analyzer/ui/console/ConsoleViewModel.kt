package com.nfcsecurity.analyzer.ui.console

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class ConsoleViewModel @Inject constructor() : ViewModel() {

    private val _output = MutableLiveData<String>("")
    val output: LiveData<String> = _output

    private val sb = StringBuilder("NFC PHANTOM v2.0 // READY\n──────────────────────\n")
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun log(message: String) {
        val time = timeFormat.format(Date())
        sb.appendLine("[$time] $message")
        _output.postValue(sb.toString())
    }

    fun clear() {
        sb.clear()
        sb.append("NFC PHANTOM v2.0 // READY\n──────────────────────\n")
        _output.value = sb.toString()
    }

    fun processCommand(cmd: String): String {
        log("$ $cmd")
        return when (cmd.trim().lowercase()) {
            "help" -> {
                val help = """
                    Commands:
                      help      - show this help
                      clear     - clear terminal
                      status    - show NFC adapter status
                      scan      - trigger NFC scan
                      keys      - list known keys
                      version   - show version
                """.trimIndent()
                log(help)
                help
            }
            "clear" -> { clear(); "" }
            "version" -> { log("NFC Phantom v2.0 — Cyberpunk Edition"); "" }
            "keys" -> {
                val keyList = com.nfcsecurity.analyzer.core.attack.KeyDictionary.DEFAULT_KEYS
                    .joinToString("\n") { it.joinToString("") { b -> "%02X".format(b) } }
                log("Known keys (${com.nfcsecurity.analyzer.core.attack.KeyDictionary.DEFAULT_KEYS.size}):\n$keyList")
                ""
            }
            "status" -> { log("NFC adapter: active | Mode: foreground dispatch"); "" }
            else -> { log("[?] Unknown command: $cmd — type 'help'"); "" }
        }
    }
}
