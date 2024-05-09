#Author: Ted Ljungsten
#
#Date: 06/05/2024
#


import sqlite3
import re


def filter_function_table(merged_db_path):

    # Connect to the database
    conn = sqlite3.connect(merged_db_path)
    cursor = conn.cursor()

    # Create a new table called "filteredfunction"
    cursor.execute('CREATE TABLE IF NOT EXISTS filteredfunction (id INT,address1 BIGINT,name1 TEXT,address2 BIGINT,name2 TEXT,similarity DOUBLE PRECISION,confidence DOUBLE PRECISION,flags INTEGER,algorithm SMALLINT,evaluate BOOLEAN,commentsported BOOLEAN,basicblocks INTEGER,edges INTEGER,instructions INTEGER,UNIQUE(address1, address2),PRIMARY KEY(id),FOREIGN KEY(algorithm) REFERENCES functionalgorithm(id))')  

    # Check if the "filteredfunction" table is empty
    cursor.execute("SELECT COUNT(*) FROM filteredfunction")
    result = cursor.fetchone()
    if result[0] == 0:
        # Copy rows from "function" table to "filteredfunction" table where "similarity" is less than 1
        cursor.execute('INSERT INTO filteredfunction SELECT * FROM function WHERE similarity < 1')

    # Commit the changes and close the connection
    conn.commit()
    conn.close()


def create_function_list(database_path):
    # Connect to the database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    # Retrieve function names from the database
    cursor.execute("SELECT name1 FROM filteredfunction")  
    function_names_apk1 = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT name2 FROM filteredfunction")  
    function_names_apk2 = [row[0] for row in cursor.fetchall()]

    # Close the database connection
    conn.close()
    print(f"Total function names from apk1 retrieved: {len(function_names_apk1)}")
    print(f"Total function names from apk2 retrieved: {len(function_names_apk2)}")

    return function_names_apk1, function_names_apk2


    # Close the database connection
    conn.close()
    print(f"Total function names from apk1 retrieved: {len(function_names_apk1)}")
    print(f"Total function names from apk2 retrieved: {len(function_names_apk2)}")


def find_lines_with_words(filename, target_words):
    found_lines = []  # Define the variable "found_lines" as an empty list
    line_counter = 0  # Initialize a line counter variable

    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            line_counter += 1  # Increment the line counter
            if "org::" in line:  # Check if the line contains "void"
                for word in target_words:
                    if word in line:
                        found_lines.append((word, line_counter))  # Append the word, line number
                        target_words.remove(word)  # Remove the found word from the target_words list
                        break
    
    return found_lines



def categorize_functions(functions, important, unimportant):
    categorized_functions = {'important': [], 'unimportant': [], 'unknown': []}

    functions = [str(obj) for obj in functions]
    
    functions = [word.capitalize() for word in functions]
    important = [word.capitalize() for word in important]
    unimportant = [word.capitalize() for word in unimportant]

    for function in functions:
        for word in important:
            if word in function:  # Convert keyword to lowercase before comparison
                categorized_functions['important'].append(function)
                break
        else:
            for word in unimportant:
                if word in function:  # Convert keyword to lowercase before comparison
                    categorized_functions['unimportant'].append(function)
                    break
            else:
                categorized_functions['unknown'].append(function)

    return categorized_functions

def read_keyword_list(file_path):
    keyword_list = []
    with open(file_path, 'r') as file:
        for line in file:
            keyword_list.append(line.strip())
        print(f"Total keywords read from {file_path}: {len(keyword_list)}")
    return keyword_list


def main():
    merged_db_path = "C:/Users/tedlj/OneDrive/Desktop/output7.2.0-7.2.3/unpacked_Signal_7.2.3_Apkpure/merged_bindiff_results.db"
    c_file_path = "C:/Users/tedlj/OneDrive/Desktop/output7.2.0-7.2.3/unpacked_Signal_7.2.3_Apkpure/classes5.c"
    

    important_list = read_keyword_list('important_keywords.txt')
    unimportant_list = read_keyword_list('unimportant_keywords.txt')
    
    
    filter_function_table(merged_db_path)
    function_names_apk1, function_names_apk2 = create_function_list(merged_db_path)
    found_lines = find_lines_with_words(c_file_path, function_names_apk1)

    categorized_functions = categorize_functions(function_names_apk1, important_list, unimportant_list)
    
    with open('categorized_output.txt', 'w') as file:
        file.write("Categorized Functions:\n")
        file.write("---------------------\n")
        file.write("Important Functions:\n")
        for function in categorized_functions['important']:
            file.write(function + "\n")
        file.write("---------------------\n")
        file.write("Unimportant Functions:\n")
        for function in categorized_functions['unimportant']:
            file.write(function + "\n")
        file.write("---------------------\n")
        file.write("Unknown Functions:\n")
        for function in categorized_functions['unknown']:
            file.write(function + "\n")
        file.write("---------------------\n")

if __name__ == "__main__":
    main()