package com.nfcsecurity.analyzer.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.data.ScanHistoryEntity
import com.nfcsecurity.analyzer.databinding.ActivityHistoryBinding
import com.nfcsecurity.analyzer.databinding.ItemScanHistoryBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@AndroidEntryPoint
class HistoryActivity : AppCompatActivity() {

    private lateinit var binding: ActivityHistoryBinding
    private val viewModel: MainViewModel by viewModels()
    private lateinit var adapter: HistoryAdapter
    private val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHistoryBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.scan_history)

        adapter = HistoryAdapter(dateFormat) { entity ->
            // Open details for this entity (future)
        }
        binding.recyclerHistory.layoutManager = LinearLayoutManager(this)
        binding.recyclerHistory.adapter = adapter

        binding.btnClearHistory.setOnClickListener {
            viewModel.clearHistory()
        }

        lifecycleScope.launch {
            viewModel.scanHistory.collect { list ->
                adapter.submitList(list)
                binding.tvEmpty.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }
}

class HistoryAdapter(
    private val dateFormat: SimpleDateFormat,
    private val onClick: (ScanHistoryEntity) -> Unit
) : ListAdapter<ScanHistoryEntity, HistoryAdapter.ViewHolder>(DiffCallback()) {

    inner class ViewHolder(val binding: ItemScanHistoryBinding) :
        RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemScanHistoryBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val entity = getItem(position)
        with(holder.binding) {
            tvCardType.text = entity.cardType
            tvUid.text = "UID: ${entity.uid}"
            tvManufacturer.text = entity.manufacturer
            tvDate.text = dateFormat.format(Date(entity.scannedAt))
            tvRisk.text = entity.overallRisk
            val ctx = root.context
            val riskColor = when (entity.overallRisk.uppercase()) {
                "CRITICAL", "HIGH" -> ctx.getColor(R.color.risk_high)
                "MEDIUM" -> ctx.getColor(R.color.risk_medium)
                else -> ctx.getColor(R.color.risk_low)
            }
            tvRisk.setTextColor(riskColor)
            root.setOnClickListener { onClick(entity) }
        }
    }

    class DiffCallback : DiffUtil.ItemCallback<ScanHistoryEntity>() {
        override fun areItemsTheSame(a: ScanHistoryEntity, b: ScanHistoryEntity) = a.id == b.id
        override fun areContentsTheSame(a: ScanHistoryEntity, b: ScanHistoryEntity) = a == b
    }
}
