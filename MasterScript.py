import subprocess
import os
import zipfile
import glob
import sqlite3
from tkinter import Tk, filedialog
import re


def select_files():
    """Open a file dialog to select APK files."""
    Tk().withdraw()
    filename = filedialog.askopenfilename(title="Select APK file", filetypes=[("APK Files", "*.apk")])
    return filename


def unpack_apk(apk_path, output_dir):
    """Unpack APK if it hasn't been unpacked yet."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.listdir(output_dir):
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        print(f"APK unpacked at {output_dir}")
    else:
        print(f"APK has already been unpacked at {output_dir}, skipping unpacking.")


def analyze_with_ghidra(dex_files, output_dir, apk_name):
    """Run Ghidra headless analysis and export both BinExport and combined C/C++ code, appending dex file number to addresses."""
    ghidra_headless = "C:/Users/adamm/Thesis/Ghidra-Bindiff/ghidra_11.0.2_PUBLIC/support/analyzeHeadless.bat"
    project_path = f"C:/Users/adamm/Thesis/Ghidra-Bindiff/projects/{apk_name}"
    if not os.path.exists(project_path):
        os.makedirs(project_path)
    dex_number = 1  # Start counting dex files from 1
    for dex_path in dex_files:
        base_name = os.path.splitext(os.path.basename(dex_path))[0]
        bin_export_path = os.path.join(output_dir, base_name + ".BinExport")
        c_output_path = os.path.join(output_dir, base_name + ".c")
        analysis_marker = bin_export_path + "_analysis_done.marker"
        if os.path.exists(analysis_marker):
            print(f"Analysis already completed for {dex_path}, skipping analysis.")
            continue
        args = [
            ghidra_headless, project_path, "tempProject", "-import", dex_path,
            "-postScript", "ExportBinAndC", bin_export_path, c_output_path,
            "-scriptPath",
            "C:/Users/adamm/Thesis/Ghidra-Bindiff/ghidra_11.0.2_PUBLIC/Ghidra/Features/Base/ghidra_scripts",
            "-deleteProject"
        ]
        subprocess.run(args, check=True)
        print(f"Analysis and export completed for {dex_path}")
        with open(analysis_marker, 'w') as f:
            f.write("Analysis completed.")
        dex_number += 1


def merge_c_files(output_dir):
    """Merge all C files into a single file."""
    c_files = glob.glob(os.path.join(output_dir, "*.c"))
    merged_c_path = os.path.join(output_dir, "merged_code.c")
    with open(merged_c_path, 'w', encoding='utf-8') as merged_file:
        for c_file in c_files:
            with open(c_file, 'r', encoding='utf-8') as file:
                merged_file.write(file.read() + "\n")
    print("Merged C files into:", merged_c_path)


def run_bindiff(binexport1, binexport2, output_file):
    """Run BinDiff on two .BinExport files if analysis hasn't been done."""
    analysis_marker = output_file + "_analysis_done.marker"
    if not os.path.exists(analysis_marker):
        bindiff_executable = "C:/Program Files/BinDiff/bin/bindiff.exe"
        print(f"Running BinDiff on: {binexport1} and {binexport2}")
        bindiff_cmd = [bindiff_executable, '--primary=' + binexport1, '--secondary=' + binexport2,
                       '--output_dir=' + os.path.dirname(output_file)]
        subprocess.run(bindiff_cmd, check=True)
        print(f"BinDiff analysis completed for: {output_file}")
        with open(analysis_marker, 'w') as f:
            f.write("Analysis completed.")


def modify_schema(schema):
    """Modify the schema to remove UNIQUE constraints and fix syntax errors."""
    # Remove UNIQUE constraints but keep the rest of the schema intact
    schema = re.sub(r",?\s*UNIQUE\([^)]+\)", "", schema, flags=re.IGNORECASE)
    # Ensure there are no trailing commas before closing parenthesis
    schema = re.sub(r",\s*\)", ")", schema)
    return schema


def merge_bindiff_files(output_dir):
    """Merge BinDiff SQLite files into one, appending .dex numbers to addresses, and allowing non-unique entries."""
    all_bindiff_files = glob.glob(os.path.join(output_dir, "*.bindiff"))
    if len(all_bindiff_files) > 1:
        merged_db_path = os.path.join(output_dir, "merged_bindiff_results.db")

        with sqlite3.connect(merged_db_path) as merged_conn:
            merged_cursor = merged_conn.cursor()

            print(f"Total BinDiff files found: {len(all_bindiff_files)}")

            for index, bindiff_file in enumerate(all_bindiff_files):
                dex_number = extract_dex_number(bindiff_file)
                print(f"Processing BinDiff file {index + 1}/{len(all_bindiff_files)}: {bindiff_file}")

                with sqlite3.connect(bindiff_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchall()

                    for table_name, in tables:
                        print(f"Processing table: {table_name}")
                        cursor.execute(f"SELECT sql FROM sqlite_master WHERE name='{table_name}'")
                        schema = cursor.fetchone()[0]

                        # Modify schema to remove UNIQUE constraints
                        schema = modify_schema(schema)

                        # Ensure the table is created in the merged database
                        try:
                            merged_cursor.execute(schema)
                        except sqlite3.OperationalError:
                            print(f"Table {table_name} already exists. Skipping creation.")

                        # Merge data from the current table
                        cursor.execute(f"SELECT * FROM {table_name}")
                        rows = cursor.fetchall()
                        print(f"Found {len(rows)} rows in table {table_name}.")

                        for row in rows:
                            new_row = list(row)
                            if len(new_row) > 1 and 'address1' in schema:  # Check if address1 can be appended
                                new_row[1] = f"{new_row[1]}#{dex_number}"
                            if len(new_row) > 3 and 'address2' in schema:  # Check if address2 can be appended
                                new_row[3] = f"{new_row[3]}#{dex_number}"

                            # Check for "id" column
                            if "id" in schema:
                                # Generate unique ID if necessary
                                new_id = generate_unique_id(merged_cursor, table_name)
                                if new_id is not None:
                                    new_row = (new_id,) + tuple(new_row[1:])
                            placeholders = ', '.join(['?' for _ in new_row])
                            try:
                                merged_cursor.execute(f"INSERT INTO {table_name} VALUES ({placeholders})", new_row)
                            except sqlite3.IntegrityError:
                                print(f"Duplicate entry for table {table_name}: {new_row}")

            print(f"Merged BinDiff results saved to {merged_db_path}.")
    else:
        print("No need to merge, only one Bindiff file present.")


def extract_dex_number(bindiff_file):
    """Extracts the dex number from the BinDiff file name based on the provided format."""
    # Print the full path for clarity
    print(f"Debug: Full path being processed: {bindiff_file}")

    # Extracting filename from the path for regex matching
    filename = os.path.basename(bindiff_file)
    print(f"Debug: Filename extracted for regex matching: {filename}")

    # Define regex pattern to extract the number part for new filename pattern
    # This pattern matches 'classes', optionally followed by a number, and captures the number
    pattern = r'classes(\d*)_vs_classes\1.BinDiff'
    match = re.search(pattern, filename)

    if match:
        dex_number = match.group(1) if match.group(1) else '1'  # Default to '1' if no number follows 'classes'
        print(f"Debug: Dex number extracted successfully: {dex_number}")
        return dex_number
    else:
        print("Debug: No match found, regex pattern used:", pattern)
        return 'unknown'


def generate_unique_id(cursor, table_name):
    """Generate a unique ID for a table."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()

    # Check if the table has an "id" column
    id_column_exists = any(col[1] == "id" for col in columns)

    if id_column_exists:
        # If an "id" column exists, retrieve the maximum ID
        cursor.execute(f"SELECT MAX(id) FROM {table_name}")
        max_id = cursor.fetchone()[0]
        return max_id + 1 if max_id is not None else 1
    else:
        # If no "id" column exists, return None
        return None


def main():
    apk1 = select_files()
    apk2 = select_files()
    unpack_dir1 = f"output/unpacked_{os.path.splitext(os.path.basename(apk1))[0]}"
    unpack_dir2 = f"output/unpacked_{os.path.splitext(os.path.basename(apk2))[0]}"
    unpack_apk(apk1, unpack_dir1)
    unpack_apk(apk2, unpack_dir2)
    dex_files1 = glob.glob(os.path.join(unpack_dir1, "*.dex"))
    dex_files2 = glob.glob(os.path.join(unpack_dir2, "*.dex"))
    analyze_with_ghidra(dex_files1, unpack_dir1, os.path.splitext(os.path.basename(apk1))[0])
    analyze_with_ghidra(dex_files2, unpack_dir2, os.path.splitext(os.path.basename(apk2))[0])
    for dex_file1, dex_file2 in zip(sorted(dex_files1), sorted(dex_files2)):
        binexport1 = os.path.splitext(dex_file1)[0] + ".BinExport"
        binexport2 = os.path.splitext(dex_file2)[0] + ".BinExport"
        output_file = os.path.join(unpack_dir1, os.path.basename(binexport1).replace('.BinExport', '_diff'))
        run_bindiff(binexport1, binexport2, output_file)
    merge_bindiff_files(unpack_dir1)
    merge_c_files(unpack_dir1)
    merge_c_files(unpack_dir2)


if __name__ == "__main__":
    main()
