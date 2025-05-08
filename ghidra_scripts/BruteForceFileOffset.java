import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.disassemble.*;

public class BruteForceFileOffset extends GhidraScript {
    public void run() throws Exception {
        int startIndex = 0;
        int maxIndex = 2048;
        boolean found = false;
        Disassembler disassembler = Disassembler.getDisassembler(currentProgram, monitor, null);
        
        for (int i = startIndex; i < maxIndex; i += 4) {
            Address address = toAddr(i);
            DisassembleResult result = disassembler.disassemble(address, null);
            if (result.disassembledAny()) {
                println("<fileOffset>" + String.valueOf(i) + "</fileOffset>");
                found = true;
                break;
            }
        }
        
        if (!found) {
            println("<fileOffset>" + String.valueOf(-1) + "</fileOffset>");
        }
    }
}
