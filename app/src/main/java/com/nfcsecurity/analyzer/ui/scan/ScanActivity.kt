package com.nfcsecurity.analyzer.ui.scan

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.nfcsecurity.analyzer.ui.MainActivity

// Legacy stub — scan is now handled in ScanFragment within MainActivity
class ScanActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}
