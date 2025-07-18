package findcrypt;

/**
 * A cryptographic constant we can search for
 *
 * @author torgo
 */
public class CryptSignature {
	private final String name;
	private transient final byte[] data;
	private final String hexBytes;

	public CryptSignature(String name, String hexBytes) {
		this.name = name;
		this.hexBytes = hexBytes;
		this.data = hexStringToByteArray(this.hexBytes);
	}

	public byte[] getBytes() {
		return this.data;
	}

	public String getName() {
		return this.name;
	}

	public String getHexBytes() {
		return this.hexBytes;
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

}
