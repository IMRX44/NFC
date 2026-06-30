package com.nfcsecurity.analyzer.ui

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.view.View
import android.view.animation.DecelerateInterpolator
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.databinding.ActivityMainBinding
import com.nfcsecurity.analyzer.ui.attack.AttackFragment
import com.nfcsecurity.analyzer.ui.console.ConsoleFragment
import com.nfcsecurity.analyzer.ui.home.HomeFragment
import com.nfcsecurity.analyzer.ui.scan.ScanFragment
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    lateinit var binding: ActivityMainBinding
    val viewModel: MainViewModel by viewModels()
    private var nfcAdapter: NfcAdapter? = null
    private lateinit var pendingIntent: PendingIntent

    private val homeFragment = HomeFragment()
    private val scanFragment = ScanFragment()
    private val attackFragment = AttackFragment()
    private val consoleFragment = ConsoleFragment()
    private val historyFragment = com.nfcsecurity.analyzer.ui.HistoryFragment()

    private var activeFragment: Fragment = homeFragment

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        setupPendingIntent()
        setupFragments()
        setupBottomNav()
        startRadarAnimation()
    }

    private fun setupPendingIntent() {
        pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )
    }

    private fun setupFragments() {
        supportFragmentManager.beginTransaction().apply {
            add(R.id.fragment_container, homeFragment, "home")
            add(R.id.fragment_container, scanFragment, "scan").hide(scanFragment)
            add(R.id.fragment_container, attackFragment, "attack").hide(attackFragment)
            add(R.id.fragment_container, consoleFragment, "console").hide(consoleFragment)
            add(R.id.fragment_container, historyFragment, "history").hide(historyFragment)
        }.commit()
    }

    private fun setupBottomNav() {
        binding.bottomNav.setOnItemSelectedListener { item ->
            val target = when (item.itemId) {
                R.id.nav_home -> homeFragment
                R.id.nav_scan -> scanFragment
                R.id.nav_attack -> attackFragment
                R.id.nav_console -> consoleFragment
                R.id.nav_history -> historyFragment
                else -> return@setOnItemSelectedListener false
            }
            switchFragment(target)
            true
        }
    }

    private fun switchFragment(target: Fragment) {
        if (target == activeFragment) return
        supportFragmentManager.beginTransaction()
            .setCustomAnimations(R.anim.fade_in, R.anim.fade_in)
            .hide(activeFragment)
            .show(target)
            .commit()
        activeFragment = target
    }

    private fun startRadarAnimation() {
        // Radar pulse on home fragment NFC icon
        // The HomeFragment manages its own animation
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TAG_DISCOVERED == intent.action ||
            NfcAdapter.ACTION_TECH_DISCOVERED == intent.action ||
            NfcAdapter.ACTION_NDEF_DISCOVERED == intent.action
        ) {
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            tag?.let {
                viewModel.processNfcTag(it)
                // Switch to scan tab to show results
                binding.bottomNav.selectedItemId = R.id.nav_scan
            }
        }
    }
}
