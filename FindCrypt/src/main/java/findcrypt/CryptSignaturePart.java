package findcrypt;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;

public class CryptSignaturePart {

	String name;
	int index;
	byte[] data;
	String encodedStr;
	int gap; // max number of bytes between preceding part and this part
	Set<Address> foundAddrs;
	CryptSignature sig;

	private CryptSignaturePart(String name, int index, String hexStr) {
		this.name = name;
		this.index = index;
		data = hexStringToByteArray(hexStr);
		encodedStr = new String(data, StandardCharsets.ISO_8859_1);
		foundAddrs = new HashSet<>();
	}

	// constructor for the first part of a signature
	public CryptSignaturePart(String name, String hexStr, CryptSignature sig) {
		this(name, 0, hexStr);
		this.sig = sig;
		gap = 0;
	}

	// constructor for all subsequent parts of a signature
	public CryptSignaturePart(String name, int index, String hexStr, int gap) {
		this(name, index, hexStr);
		this.gap = gap;
		sig = null;
	}

	public String getAsStr() {
		return encodedStr;
	}

	public int getLength() {
		return data.length;
	}

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public void markFoundAtAddress(Address address) {
		foundAddrs.add(address);
	}

	public Address getMatchedAddress(Address spanStart) {
		try {
			AddressRange range = new AddressRangeImpl(spanStart, gap + 1);
			for (Address addr : foundAddrs) {
				if (range.contains(addr))
					return addr;
			}
		} catch (AddressOverflowException e) {
		}
		return null;
	}

	public CryptSignature getSig() {
		return sig;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		CryptSignaturePart other = (CryptSignaturePart) o;
		return name.equals(other.name) && other.index == index;
	}

	@Override
	public int hashCode() {
		return Objects.hash(name, index);
	}
}
