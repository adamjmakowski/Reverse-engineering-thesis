# Reverse-engineering-thesis
Code for reverse engineering 2 APK's with Ghidra and performing a diff operation with BinDiff. 

Usage:
1. Modify the Master Script to specify the locations to Ghidra and Bindiff directories.
2. Place the ExportBinAndC.java (or ExportBinExport if you prefer) file in Ghidra > Features > Base > ghidra_scripts.
3. Run the Master Script, you will be prompted to select the APK files you want to process.

   All Output files are placed in Output > unpacked_{name of APK file}
   There will be two unpacked APK directories, the output files will be placed in the first one you selected when running the program.
   
The Output is currently stored in a .db file, if you'd rather see it in BinDiff then comment out the merge bindiff method call at the end.

Dependencies:
- tkinter
- BinExport extension for Ghidra installed
