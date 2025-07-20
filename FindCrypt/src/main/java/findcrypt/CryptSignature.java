package findcrypt;

import java.util.Arrays;

/**
 * A cryptographic constant we can search for
 *
 * @author torgo
 */
public class CryptSignature {
	private final String name;
	private transient final byte[] data;
	private transient final byte[] prefix;
	private final String hexBytes;
	
	private static final int PREFIX_SIZE = 8;

	public CryptSignature(String name, String hexBytes) {
		this.name = name;
		this.hexBytes = hexBytes;
		this.data = hexStringToByteArray(this.hexBytes);
		if (this.data.length > PREFIX_SIZE) {
			this.prefix = Arrays.copyOfRange(this.data, 0, PREFIX_SIZE); 
		} else {
			this.prefix = null;
		}
	}

	public byte[] getBytes() {
		return this.data;
	}
	
	public byte[] getPrefixBytes() {
		return this.prefix; 
	}

	public boolean isLarge() {
		return this.prefix != null;
	}

	public String getName() {
		return this.name;
	}

	public String getHexBytes() {
		return this.hexBytes;
	}

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}
