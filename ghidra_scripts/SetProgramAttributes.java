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
import ghidra.program.disassemble.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

public class SetProgramAttributes extends GhidraScript {
    public void run() throws Exception {
        Program program = currentProgram;
        Memory memory = program.getMemory();
        AddressFactory addressFactory = program.getAddressFactory();
        AddressSpace space = addressFactory.getDefaultAddressSpace();
        DomainFile domainFile = program.getDomainFile();
        DomainFolder addressFolder = domainFile.getParent();
        String addressStr = addressFolder.getName();
        long address = Long.parseLong(addressStr, 16);
	println("Address: " + addressStr);
        // Set your desired base address
        Address baseAddress = toAddr(address);
        
        // Simulate reading from a file
        program.setImageBase(baseAddress, true);
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        disassembler.disassemble(baseAddress, null);
        
        println("Memory block created at " + baseAddress.toString());
    }
}
