package com.nfcsecurity.analyzer.ui.console

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.nfcsecurity.analyzer.databinding.FragmentConsoleBinding
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class ConsoleFragment : Fragment() {

    private var _binding: FragmentConsoleBinding? = null
    private val binding get() = _binding!!
    private val consoleViewModel: ConsoleViewModel by activityViewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentConsoleBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        consoleViewModel.output.observe(viewLifecycleOwner) { text ->
            binding.tvConsoleOutput.text = text
            binding.scrollTerminal.post {
                binding.scrollTerminal.fullScroll(View.FOCUS_DOWN)
            }
        }

        binding.btnClearConsole.setOnClickListener {
            consoleViewModel.clear()
        }

        binding.etConsoleInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEND) {
                sendCommand()
                true
            } else false
        }

        binding.btnSendCmd.setOnClickListener { sendCommand() }
    }

    private fun sendCommand() {
        val cmd = binding.etConsoleInput.text.toString()
        if (cmd.isNotBlank()) {
            consoleViewModel.processCommand(cmd)
            binding.etConsoleInput.text?.clear()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
