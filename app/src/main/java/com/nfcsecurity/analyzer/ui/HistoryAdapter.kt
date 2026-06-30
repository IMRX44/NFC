package com.nfcsecurity.analyzer.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nfcsecurity.analyzer.R
import com.nfcsecurity.analyzer.data.ScanHistoryEntity
import com.nfcsecurity.analyzer.databinding.ItemScanHistoryBinding
import java.text.SimpleDateFormat
import java.util.*

class HistoryAdapter(
    private val onClick: (ScanHistoryEntity) -> Unit = {}
) : ListAdapter<ScanHistoryEntity, HistoryAdapter.ViewHolder>(DiffCallback()) {

    private val dateFormat = SimpleDateFormat("MMM dd HH:mm", Locale.getDefault())

    inner class ViewHolder(val binding: ItemScanHistoryBinding) :
        RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemScanHistoryBinding.inflate(LayoutInflater.from(parent.context), parent, false)
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
            tvRisk.setTextColor(when (entity.overallRisk.uppercase()) {
                "CRITICAL", "HIGH" -> ctx.getColor(R.color.neon_red)
                "MEDIUM" -> ctx.getColor(R.color.neon_yellow)
                else -> ctx.getColor(R.color.neon_green)
            })
            root.setOnClickListener { onClick(entity) }
        }
    }

    class DiffCallback : DiffUtil.ItemCallback<ScanHistoryEntity>() {
        override fun areItemsTheSame(a: ScanHistoryEntity, b: ScanHistoryEntity) = a.id == b.id
        override fun areContentsTheSame(a: ScanHistoryEntity, b: ScanHistoryEntity) = a == b
    }
}
