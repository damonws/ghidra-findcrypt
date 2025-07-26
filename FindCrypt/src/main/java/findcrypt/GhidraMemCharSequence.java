package findcrypt;

import java.util.Arrays;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class GhidraMemCharSequence implements CharSequence {

	private byte[] bytes;

	public GhidraMemCharSequence(Memory mem, AddressRange range, MessageLog log) throws MemoryAccessException {

		bytes = new byte[(int) range.getLength()];
		mem.getBytes(range.getMinAddress(), bytes);
	}

	private GhidraMemCharSequence(byte[] bytes) {
		this.bytes = bytes;
	}

	@Override
	public int length() {
		return bytes.length;
	}

	@Override
	public char charAt(int index) {
		return (char) (bytes[index] & 0xff);
	}

	@Override
	public CharSequence subSequence(int start, int end) {
		return new GhidraMemCharSequence(Arrays.copyOfRange(bytes, start, end));
	}

}
