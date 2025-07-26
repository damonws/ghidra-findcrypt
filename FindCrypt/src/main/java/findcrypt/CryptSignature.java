package findcrypt;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

/**
 * A cryptographic constant we can search for.
 * 
 * formatted as a hex bytes, with two simple wildcards: "{N}" from 0-N bytes
 * that can by anything and "*" equivalent to "{9}".
 *
 * Thus, a constant is a collection of one or more hex strings to match, with
 * variable length gaps between the parts.
 */
public class CryptSignature implements Comparable<CryptSignature> {
	private final String name;
	private final String comment;
	private final String hexBytes;
	private transient List<CryptSignaturePart> parts;
	private transient int length;
	private transient boolean everFound;

	public CryptSignature(String name, String comment, String hexBytes) {
		this.name = name;
		this.comment = comment;
		this.hexBytes = hexBytes;
		parts = new ArrayList<>();
		length = 0;
		int gap = 0;
		int index = 0;
		for (String s : hexBytes.splitWithDelimiters("(\\{\\d+\\})|\\*", 0)) {
			if (s.equals("*")) {
				gap = 9;
			} else if (s.startsWith("{")) {
				gap = Integer.parseInt(s.substring(1, s.length() - 1));
			} else {
				if (index == 0) {
					parts.add(new CryptSignaturePart(name, s, this));
				} else {
					parts.add(new CryptSignaturePart(name, index, s, gap));
				}
				index++;
				length += s.length() / 2;
			}
		}
		everFound = false;
	}

	// return an AddressSet of the (potentially non-contiguous) addresses containing
	// the signature match, or null if there is no match
	public AddressSet isMatched(Address addr) {
		AddressSet match = new AddressSet();
		for (CryptSignaturePart part : parts) {
			Address partAddr = part.getMatchedAddress(addr);
			if (partAddr == null)
				return null;
			match.add(partAddr, partAddr.add(part.getLength() - 1));
			addr = partAddr.add(part.getLength());
		}
		return match;
	}

	public String getName() {
		return name;
	}

	public String getComment() {
		if (comment == null)
			return "";
		return comment;
	}

	public String getHexBytes() {
		return hexBytes;
	}

	public int getLength() {
		return length;
	}

	public void setEverFound() {
		everFound = true;
	}

	public boolean getEverFound() {
		return everFound;
	}

	@Override
	public int compareTo(CryptSignature o) {
		int diff = o.getLength() - getLength();
		if (diff != 0)
			return diff;
		return name.compareTo(o.getName());
	}

	public List<CryptSignaturePart> getParts() {
		return parts;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		CryptSignature other = (CryptSignature) o;
		return name.equals(other.name);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
	}
}