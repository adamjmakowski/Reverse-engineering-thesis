/*
* Author: Adam Makowski
* 25/04/2024
*/

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSet;
import java.io.*;

import com.google.security.binexport.BinExportExporter;

public class ExportBinAndC extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Arguments for paths
        String binExportPath = getScriptArgs()[0]; // First argument: path for the .BinExport file
        String cOutputPath = getScriptArgs()[1];   // Second argument: path for the .C file
        
        File binExportFile = new File(binExportPath);
        File cOutputFile = new File(cOutputPath);

        // Export the binary data using BinExport
        AddressSet addressSet = new AddressSet(currentProgram.getMemory());
        BinExportExporter binExporter = new BinExportExporter();
        binExporter.export(binExportFile, currentProgram, addressSet, monitor);
        println("Export successful to " + binExportFile.getAbsolutePath());

        // Decompile and export C/C++ code
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter writer = new PrintWriter(new FileOutputStream(cOutputFile, false))) { // False to overwrite any existing content
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                DecompileResults results = ifc.decompileFunction(func, 60, monitor);
                if (results != null && results.getDecompiledFunction() != null) {
                    String decompiledCode = results.getDecompiledFunction().getC();
                    writer.println("// Function: " + func.getName());
                    writer.println(decompiledCode);
                    writer.println();
                }
            }
        } catch (IOException e) {
            println("Error writing to C output file: " + e.getMessage());
        }
    }
}
