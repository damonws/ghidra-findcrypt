package findcrypt;

import java.io.Reader;
import java.util.ArrayList;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.util.Msg;

/**
 * A simple data structure that deserializes {@link CryptSignature} objects from
 * a file.
 */
public class CryptDatabase {
	private final ArrayList<CryptSignature> signatures;

	public CryptDatabase() {
		signatures = new ArrayList<>();
	}

	public void parse(Reader reader) {
		Gson gson = new Gson();
		final ArrayList<CryptSignature> loadedSignatures = gson.fromJson(reader,
				new TypeToken<ArrayList<CryptSignature>>() {
				}.getType());
		loadedSignatures.forEach(
				signature -> addSignature(signature.getName(), signature.getComment(), signature.getHexBytes()));
	}

	public ArrayList<CryptSignature> getSignatures() {
		return signatures;
	}

	public int getNumSignatures() {
		return signatures.size();
	}

	public int getNumFound() {
		int found = 0;
		for (CryptSignature sig : signatures) {
			if (sig.getEverFound())
				found++;
		}
		return found;
	}

	private void addSignature(String name, String comment, String hexString) {
		CryptSignature sig = new CryptSignature(name, comment, hexString);
		signatures.add(sig);
		Msg.debug(this, String.format("Added signature: %s", sig.getName()));
	}
}
