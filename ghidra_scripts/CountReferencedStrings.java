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
//This script counts the references to existing strings.
//@category Analysis

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.DefinedStringIterator;
import ghidra.program.model.listing.Data;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import java.io.FileWriter;

public class CountReferencedStrings extends GhidraScript {

	@Override
	public void run() throws Exception {

		monitor.setMessage("Finding Strings with References");
		int referencedCount = 0;
		int totalCount = 0;
		DomainFile domainFile = currentProgram.getDomainFile();
		String name = domainFile.getName();
		DomainFolder domainFolder = domainFile.getParent();
		DomainFolder offsetFolder = domainFolder.getParent();
		String address = domainFolder.getName();

		DefinedStringIterator it = DefinedStringIterator.forProgram(currentProgram);
		while (it.hasNext()) {
			Data nextData = it.next();
			Address strAddr = nextData.getMinAddress();
			int refCount = currentProgram.getReferenceManager().getReferenceCountTo(strAddr);
			totalCount++;
			referencedCount += refCount;
		}
		String workspaceDirectory = System.getenv("BAD_WORKSPACE");
		String xml = "<ghidra_result><referenced>" + referencedCount + "</referenced><total>" + totalCount + "</total><address>" + address + "</address><offset>" + offsetFolder.getName() + "</offset></ghidra_result>";
		FileWriter fw = new FileWriter(workspaceDirectory + "/" + name + "/results/" + offsetFolder.getName() + "/result.xml", true);
		fw.write(xml);
		fw.close();
		println("File appended to");
	}
}
