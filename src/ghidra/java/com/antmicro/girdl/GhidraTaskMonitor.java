package com.antmicro.girdl;


import com.antmicro.girdl.util.task.SimpleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class GhidraTaskMonitor implements SimpleTaskMonitor {

	private final TaskMonitor monitor;

	public GhidraTaskMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	@Override
	public void setPhase(String phase) {
		monitor.setMessage(phase);
	}

	@Override
	public void setMaximum(long work) {
		monitor.setMaximum(work);
	}

	@Override
	public void incrementProgress() {
		monitor.incrementProgress();
	}

}
