package findcrypt;

import java.util.Arrays;

/**
 * A cryptographic constant we can search for
 *
 * @author torgo
 */
public class CryptSignature implements Comparable<CryptSignature> {
	private final String name;
	private final String comment;
	private final String hexBytes;
	private transient final byte[] data;
	private transient final byte[] prefix;

	private static final int PREFIX_SIZE = 8;

	public CryptSignature(String name, String comment, String hexBytes) {
		this.name = name;
		this.comment = comment;
		this.hexBytes = hexBytes;
		data = hexStringToByteArray(this.hexBytes);
		if (data.length > PREFIX_SIZE) {
			prefix = Arrays.copyOfRange(data, 0, PREFIX_SIZE);
		} else {
			prefix = null;
		}
	}

	public byte[] getBytes() {
		return data;
	}

	public byte[] getPrefixBytes() {
		return prefix;
	}

	public boolean isLarge() {
		return prefix != null;
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

	@Override
	public int compareTo(CryptSignature o) {
		return o.getLength() - getLength();
	}

}
