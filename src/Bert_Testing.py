from transformers import RobertaTokenizer, RobertaForSequenceClassification
import torch
import sys

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load the saved model
model_path = "./fine_tuned_codebert4"
tokenizer = RobertaTokenizer.from_pretrained(model_path)
model = RobertaForSequenceClassification.from_pretrained(model_path)
model.to(device)
model.eval()

# Example code to classify
# Buffer Overflow! Oh NO!
# The results should be 9 (BF).
code_sample = """
import sqlite3

def login():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (username TEXT, password TEXT);")
    cur.execute("INSERT INTO users VALUES ('admin', 'secret');")
    conn.commit()

    user = input("Username: ")
    pwd = input("Password: ")

    # 🚨 SQL Injection vulnerability here:
    query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{pwd}'"
    print(f"[DEBUG] Running: {query}")
    cur.execute(query)

    if cur.fetchone():
        print("Login successful!")
    else:
        print("Login failed.")

    conn.close()

if __name__ == "__main__":
    login()

"""

# Tokenize
inputs = tokenizer(
    code_sample,
    return_tensors="pt",
    truncation=True,
    padding="max_length",
    max_length=512
).to(device)

# Predict
with torch.no_grad():
    outputs = model(**inputs)
    logits = outputs.logits
    predicted_class = torch.argmax(logits, dim=1).item()

print(f"Predicted vulnerability class: {predicted_class}")
sys.exit(0)