package com.antmicro.girdl;

import com.antmicro.girdl.util.log.LogConsumer;
import ghidra.util.Msg;

public class GhidraLogConsumer implements LogConsumer {

	@Override
	public void trace(Object origin, Object message) {
		Msg.trace(origin, message);
	}

	@Override
	public void info(Object origin, Object message) {
		Msg.info(origin, message);
	}

	@Override
	public void warn(Object origin, Object message) {
		Msg.warn(origin, message);
	}

	@Override
	public void error(Object origin, Object message) {
		Msg.error(origin, message);
	}

}
