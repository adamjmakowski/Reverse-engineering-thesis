/*
* Author: Adam Makowski
* 25/04/2024
*/

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import java.io.File;

import com.google.security.binexport.BinExportExporter;

public class ExportBinExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Get the current program file (assumed to be the .dex file)
        File currentDexFile = new File(getProgramFile().getAbsolutePath());
        
        // Derive the output directory from the .dex file's parent directory
        File outputDirectory = currentDexFile.getParentFile();
        
        // Construct the .binexport filename by replacing .dex with .BinExport
        String outputFileName = currentDexFile.getName().replace(".dex", ".BinExport");
        File outputFile = new File(outputDirectory, outputFileName);

        // Ensure the directory exists (though it should)
        outputDirectory.mkdirs();

        // Get the entire addressable memory
        AddressSet addrSet = new AddressSet(currentProgram.getMemory());

        // Create an exporter instance
        BinExportExporter exporter = new BinExportExporter();

        // Export the binary data
        exporter.export(outputFile, currentProgram, addrSet, monitor);
        println("Export successful to " + outputFile.getAbsolutePath());
    }
}
