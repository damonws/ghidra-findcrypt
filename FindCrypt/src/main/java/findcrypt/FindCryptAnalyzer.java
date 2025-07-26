/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package findcrypt;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import org.ahocorasick.trie.PayloadEmit;
import org.ahocorasick.trie.PayloadTrie;
import org.ahocorasick.trie.PayloadTrie.PayloadTrieBuilder;

import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer searches through program bytes to locate cryptographic
 * constants and labels them.
 */
public class FindCryptAnalyzer extends AbstractAnalyzer {

	private CryptDatabase database;

	public FindCryptAnalyzer() {
		super("Find Crypt", "Find common cryptographic constants", AnalyzerType.BYTE_ANALYZER);
		database = null;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// We're on by default
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		// We can analyze anything with bytes!
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		int totalSigCount = 0;

		// If the database hasn't yet been opened, we'll open it
		monitor.setMessage(getName() + ": loading database");
		if (database == null) {
			try {
				database = new CryptDatabase();
				ResourceFile resourceFile = Application.getModuleFile("FindCrypt", "data/database.json");
				Msg.info(this, "Loading FindCrypt signature database from file");

				Reader reader = Files.newBufferedReader(resourceFile.getFile(true).toPath());
				database.parse(reader);
			} catch (IOException e) {
				log.appendException(e);
				return false;
			}
		}

		// Consolidate duplicate signature parts before feeding to Aho-Corasick
		// also check for duplicate signature names -- subsequent code needs them to be
		// unique
		monitor.setMessage(getName() + ": consolidating signatures");
		Map<String, Set<CryptSignaturePart>> partsMap = new HashMap<>();
		Set<String> sigNames = new HashSet<>();
		for (CryptSignature sig : database.getSignatures()) {
			monitor.checkCancelled();
			if (sigNames.contains(sig.getName())) {
				log.appendMsg(getName() + " FAILED: duplicate signature name: " + sig.getName());
				return false;
			}
			sigNames.add(sig.getName());
			for (CryptSignaturePart part : sig.getParts()) {
				Set<CryptSignaturePart> partSet = partsMap.get(part.getAsStr());
				if (partSet == null) {
					partSet = new HashSet<>();
					partsMap.put(part.getAsStr(), partSet);
				}
				partSet.add(part);
			}
		}

		// Build Aho-Corasick automaton
		monitor.setMessage(getName() + ": building automaton");
		PayloadTrieBuilder<Set<CryptSignaturePart>> tb = PayloadTrie.builder();
		for (Entry<String, Set<CryptSignaturePart>> entry : partsMap.entrySet()) {
			monitor.checkCancelled();
			tb.addKeyword(entry.getKey(), entry.getValue());
		}
		PayloadTrie<Set<CryptSignaturePart>> trie = tb.build();

		// Run the automaton on each address range to find signature parts
		monitor.setMessage(getName() + ": finding signature parts");
		Map<Address, Set<CryptSignature>> cryptMap = new HashMap<>();
		for (AddressRange range : set.getAddressRanges()) {
			monitor.checkCancelled();
			try {
				// wrap memory for this address range in a datatype that Aho-Corasick can search
				GhidraMemCharSequence cs = new GhidraMemCharSequence(program.getMemory(), range, log);
				Collection<PayloadEmit<Set<CryptSignaturePart>>> emits = trie.parseText(cs);
				for (PayloadEmit<Set<CryptSignaturePart>> emit : emits) {
					// each match is a set of parts from signatures that require this pattern
					monitor.checkCancelled();
					Set<CryptSignaturePart> partSet = emit.getPayload();
					Address foundAddr = range.getMinAddress().add(emit.getStart());
					// mark each part as found at the address where this pattern was found
					for (CryptSignaturePart part : partSet) {
						part.markFoundAtAddress(foundAddr);
						if (part.getSig() != null) {
							// this is the first part of a signature -- save it to check whether all parts
							// matched in the next pass
							Set<CryptSignature> sigSet = cryptMap.get(foundAddr);
							if (sigSet == null) {
								// it's important to use a TreeSet here so the sigs are sorted
								sigSet = new TreeSet<>();
								cryptMap.put(foundAddr, sigSet);
							}
							sigSet.add(part.getSig());
						}
					}
				}
			} catch (MemoryAccessException e) {
				// just skip to next address range if this one is not readable
			}
		}

		// apply markup for the signatures that are matched
		monitor.setMessage(getName() + ": applying markup");
		for (Map.Entry<Address, Set<CryptSignature>> entry : cryptMap.entrySet()) {
			Address addr = entry.getKey();
			Set<CryptSignature> sigs = entry.getValue();
			String comment = "";
			for (CryptSignature sig : sigs) {
				monitor.checkCancelled();
				if (sig.isMatched(addr)) {
					totalSigCount++;
					sig.setEverFound();
					try {
						// Add a symbol
						program.getSymbolTable().createLabel(addr, "CRYPT_" + sig.getName(), SourceType.ANALYSIS);
						Msg.info(this, String.format("Labelled %s @ %s - %d bytes", sig.getName(), addr.toString(),
								sig.getLength()));

						// Add to comment
						if (comment.length() > 0)
							comment += System.lineSeparator();
						comment += String.format("Crypt constant %s - %d bytes", sig.getName(), sig.getLength());
						if (sig.getComment().length() > 0)
							comment += System.lineSeparator() + sig.getComment();

						// Try to create an array for the first part of the sig
						ArrayDataType dt = new ArrayDataType(new ByteDataType(), sig.getParts().get(0).getLength(), 1);
						program.getListing().createData(addr, dt);
					} catch (InvalidInputException e) {
						Msg.error(this, "signature markup failed", e);
					} catch (CodeUnitInsertionException e) {
						// We failed to attach the datatype, this is probably due to existing data
						Msg.warn(this, "Could not apply datatype for crypt constant:" + e.getMessage());
					}
				}
			}
			if (comment.length() > 0) {
				// apply comment at this address
				setPreComment(program, comment, addr);
			}
		}
		Msg.info(this, String.format("%s: %d signatures (%d unique) found at %d addresses", getName(), totalSigCount,
				database.getNumFound(), cryptMap.size()));

		return true;
	}

	private void setPreComment(Program program, String comment, Address addr) {
		// comment type parameter: new data type starting with 11.4; 'int' is deprecated
		program.getListing().setComment(addr, CommentType.PRE, comment);
	}

	@Override
	public void analysisEnded(Program program) {
		// Drop the database and end the analysis
		database = null;
		super.analysisEnded(program);
	}
}
