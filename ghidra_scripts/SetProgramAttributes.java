// Assume 'currentProgram' and 'currentAddress' are provided
// or you can define your own program and starting address

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.mem.FileBytes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

public class SetProgramAttributes extends GhidraScript {
    public void run() throws Exception {
        Program program = currentProgram;
        Memory memory = program.getMemory();
        AddressFactory addressFactory = program.getAddressFactory();
        AddressSpace space = addressFactory.getDefaultAddressSpace();
        DomainFile domainFile = currentProgram.getDomainFile();
        DomainFolder addressFolder = domainFile.getParent();
        DomainFolder offsetFolder = addressFolder.getParent();
        String addressStr = addressFolder.getName();
        String offsetStr = offsetFolder.getName();
        int address = Integer.parseInt(addressStr, 16);
        int offset = Integer.parseInt(offsetStr, 16);
	println("Address: " + addressStr);
	println("offset: " + offsetStr);
        // Set your desired base address
        Address baseAddress = space.getAddress(address);
        
        // Simulate reading from a file
        byte[] fileBytes = getBytesFromSomewhere(offset);  // <-- you need to define this part
	for (MemoryBlock block : memory.getBlocks()) {
        // Remove each block
	    memory.removeBlock(block, monitor);
	    println("Removed memory block: " + block.getName());
	}
        // Create a memory block at that base address
        MemoryBlock block = memory.createInitializedBlock(
                "Test",     // block name
                baseAddress,   // base address
                new ByteArrayInputStream(fileBytes), // input stream of file bytes
                fileBytes.length,    // size
                monitor,       // TaskMonitor
                false          // do not overlay
        );
        
        println("Memory block created at " + baseAddress.toString());
    }

    // Dummy function for example
    private byte[] getBytesFromSomewhere(int offset) throws IOException {
        Memory memory = currentProgram.getMemory();
        FileBytes fileBytes = memory.getAllFileBytes().get(0);  // Usually there's just one
        int totalInitializedBytes = (int)fileBytes.getSize();

        int fileOffset = offset;  // where you want to start reading in the file
        int size = totalInitializedBytes - fileOffset;        // how many bytes you want to load
    	println("Size: " + String.valueOf(size));
	println("totalInitializedBytes: " + String.valueOf(totalInitializedBytes));
	println("offset: " + String.valueOf(offset));
        byte[] bytes = new byte[size];
	fileBytes.getOriginalBytes(fileOffset, bytes);
        // Fill with something or read from a file
        return bytes;
    }
}
// Example: creating a new memory block at a specific base address and file offset
