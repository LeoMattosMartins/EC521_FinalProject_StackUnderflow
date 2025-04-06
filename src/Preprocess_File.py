import pandas as pd

print("Beginning Cleansing... ")

# Define a dictionary mapping vulnerability names to numeric labels
label_dict = {
    "SQL Injection": 1,
    "XSS": 2,
    "Command Injection": 3,
    "Path Traversal": 4,
    "LDAP Injection": 5,
    "Code Injection": 6,
    "XPath Injection": 7,
    "OS Commanding": 8,
    "Buffer Overflow": 9,
    "Memory Leak": 10,
    "Memory Corruption": 11,
    "Sensitive Information": 12,
    "eval": 13,
    "Arbitrary Code Execution": 14,
    "Encoding Error": 15,
    "Insecure Randomness": 16,
    "KeyError Crash": 17,
    "Code Execution": 18,
    "NullPointerException": 19,
    "DoS": 20,
    "fmt.Printf": 21,
    "ClassCastException": 22,
    "Resource Leak": 23,
    "Null Pointer Exception": 24,
    "Off by one": 25
    
}


# Load dataset
dataset_path = "C:\\Users\\bogda\\OneDrive\\Documents\\EC521\\EC521_Final_Project\\secure_programming_dpo.json"
dataset = pd.read_json(dataset_path)

# Remove the "system" column (if it exists)
if "system" in dataset.columns:
    dataset = dataset.drop(columns=["system"])

# Function to replace long vulnerability descriptions with short names
def map_vulnerability(description):
    for keyword, label_value in label_dict.items():
        if keyword.lower() in description.lower():
            return label_value  # Replace with numeric label
    return -1

# Apply the function to the "vulnerability" column
dataset["vulnerability"] = dataset["vulnerability"].apply(map_vulnerability)

# Find entries that failed to match
failed_matches = dataset[dataset["vulnerability"] == -1]

print("Finished running program.")
print(f"Failed to match {len(failed_matches)} entries.")
print("Failed locations (indexes):", failed_matches.index.tolist())

# Save the cleaned dataset (optional)
cleaned_dataset_path = "C:\\Users\\bogda\\OneDrive\\Documents\\EC521\\EC521_Final_Project\\cleaned_dataset.json"
dataset.to_json(cleaned_dataset_path, orient="records", indent=4)

print(f"Cleaned dataset saved to {cleaned_dataset_path}.")
print("Program finished successfully.")
