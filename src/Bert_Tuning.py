import pandas as pd
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification, TrainingArguments, Trainer, TrainerCallback
from torch.utils.data import Dataset
from tqdm import tqdm
import os


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
model = RobertaForSequenceClassification.from_pretrained("microsoft/codebert-base", num_labels=26)
model.to(device)
df = pd.read_json("C:\\Users\\bogda\\OneDrive\\Documents\\EC521\\EC521_Final_Project\\final_dataset.json")


class CodeDataset(Dataset):
    def __init__(self, dataframe, tokenizer, max_len=512):
        self.codes = dataframe["code"].tolist()
        self.labels = dataframe["vulnerability"].tolist()
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        code = self.codes[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=self.max_len,
            return_tensors="pt"
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(),
            "attention_mask": encoding["attention_mask"].squeeze(),
            "labels": torch.tensor(label, dtype=torch.long)
        }


train_dataset = CodeDataset(df, tokenizer)
training_args = TrainingArguments(
    output_dir="./checkpoints",
    num_train_epochs= 3,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    warmup_steps=200,
    weight_decay=0.01,
    logging_dir="./logs",
    logging_steps=100,
    save_strategy="epoch",
    eval_strategy="no",  # Updated argument here
    fp16=torch.cuda.is_available(),  
    logging_first_step=True,
)

class ProgressBarCallback(TrainerCallback):
    def __init__(self, total_steps):
        self.pbar = tqdm(total=total_steps, desc="Training Progress")
        self.total_loss = 0
        self.step_count = 0

    def on_log(self, args, state, control, logs=None, **kwargs):
        if "loss" in logs:
            self.step_count += 1
            loss = logs["loss"]
            self.total_loss += loss
            avg_loss = self.total_loss / self.step_count
            self.pbar.set_postfix({"Avg Loss": f"{avg_loss:.4f}"})
            self.pbar.update(1)

    def on_train_end(self, args, state, control, **kwargs):
        self.pbar.close()


total_steps = (len(train_dataset) // training_args.per_device_train_batch_size) * training_args.num_train_epochs


trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    tokenizer=tokenizer,
    callbacks=[ProgressBarCallback(total_steps)]
)

print("Starting training...")
trainer.train()


save_path = "./fine_tuned_codebert4" # We're on iteration 4.
os.makedirs(save_path, exist_ok=True)
model.save_pretrained(save_path)
tokenizer.save_pretrained(save_path)
print(f"Model and tokenizer saved to: {save_path}")
