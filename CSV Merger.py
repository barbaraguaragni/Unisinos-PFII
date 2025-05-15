import pandas as pd
import glob
import os

ROOT_DIR = r"E:\Documents\TCC\categorized_results"

for subdir, _, _ in os.walk(ROOT_DIR):
    if subdir == ROOT_DIR:
        continue
    
    csv_files = glob.glob(os.path.join(subdir, "*.csv"))
    if not csv_files:
        continue
    
    print(f"\nProcessing subfolder: {subdir}")
    print(f"Found {len(csv_files)} CSV files")
    
    list = []
    
    for file in csv_files:
        try:
            df = pd.read_csv(file)
            df['source_file'] = os.path.basename(file)
            list.append(df)
            print(f"Successfully read: {os.path.basename(file)}")
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    if list:
        folder_name = os.path.basename(subdir)
        output_filename = f"{folder_name}_merged.csv"
        output_path = os.path.join(subdir, output_filename)
        
        merged_df = pd.concat(list, ignore_index=True)
        merged_df.to_csv(output_path, index=False)
        print(f"Saved merged file to: {output_path}")
    else:
        print("No valid CSV files found in this subfolder")

print("\nAll subfolders processed!")