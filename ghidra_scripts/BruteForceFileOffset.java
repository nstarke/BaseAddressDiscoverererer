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

public class BruteForceFileOffset extends GhidraScript {
    public void run() throws Exception {
        int startIndex = 0;
        long maxIndex = 2 * 1024;
        Disassembler disassembler = Disassembler.getDisassembler(currentProgram, monitor, null);
        long highestAddressOffset = -1;

        for (int i = startIndex; i < maxIndex; i += 4) {
            Address address = toAddr(i);
            AddressSet result = disassembler.disassemble(address, null);
            long size = result.getNumAddresses();

            //println(String.valueOf(i) + " " + String.valueOf(size));
            Listing listing = currentProgram.getListing();
            listing.clearCodeUnits(currentProgram.getMinAddress(), currentProgram.getMaxAddress(), false);

            if (size > 10000) {
                highestAddressOffset = i;
                break;
            }
        }

        println("<fileOffset>" + String.valueOf(highestAddressOffset) + "</fileOffset>");
    }
}
