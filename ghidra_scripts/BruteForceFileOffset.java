import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.disassemble.*;
import ghidra.program.model.address.AddressSet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class BruteForceFileOffset extends GhidraScript {
    public void run() throws Exception {
        int startIndex = 0;
        Disassembler disassembler = Disassembler.getDisassembler(currentProgram, monitor, null);
        long highestAddressOffset = -1;
        int numBytes = 4;

        // Prepare byte array
        byte[] buffer = new byte[numBytes];

        // Get memory object and read bytes
        Memory memory = currentProgram.getMemory();
        AddressSetView addressSet = currentProgram.getMemory().getLoadedAndInitializedAddressSet();                                                                        
        Address minAddress = addressSet.getMinAddress();
        Address maxAddress = addressSet.getMaxAddress();
        long totalSize = maxAddress.getOffset() - minAddress.getOffset(); 
        long maxIndex = totalSize / 4;   
        for (int i = startIndex; i < maxIndex; i += 4) {
            Address address = toAddr(i);
            memory.getBytes(address, buffer);
            ByteBuffer bb = ByteBuffer.wrap(buffer);
            bb.order(ByteOrder.LITTLE_ENDIAN);  // or ByteOrder.BIG_ENDIAN

            int programBytes = bb.getInt(0); // Read the first 4 bytes as an integer
            if (programBytes == 0) {
                continue;
            }
            
            AddressSet result = disassembler.disassemble(address, null);
            long size = result.getNumAddresses();
            
            //println(String.valueOf(i) + " " + String.valueOf(size));
            Listing listing = currentProgram.getListing();
            listing.clearCodeUnits(currentProgram.getMinAddress(), currentProgram.getMaxAddress(), false);

            if (size > 1000 && programBytes != 0) {
                highestAddressOffset = i;
                break;
            }
        }

        println("<fileOffset>" + String.valueOf(highestAddressOffset) + "</fileOffset>");
    }
}
