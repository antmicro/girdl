/*
 * Copyright 2025 Antmicro
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.antmicro.girdl.util.task;

public final class RecursiveTaskMonitor {

	public static final RecursiveTaskMonitor DUMMY = new RecursiveTaskMonitor(new DummyTaskMonitor(), "");

	private long work;
	private final SimpleTaskMonitor monitor;

	public RecursiveTaskMonitor(SimpleTaskMonitor monitor, String phase) {
		this.monitor = monitor;
		monitor.setPhase(phase);
	}

	public void addWork(int amount) {
		synchronized (monitor) {
			work += amount;
			monitor.setMaximum(work);
		}
	}

	public void done() {
		synchronized (monitor) {
			monitor.incrementProgress();
		}
	}

	public long getCount() {
		return work;
	}

}
