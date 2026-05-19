import pandas as pd
import joblib
from sklearn.metrics import classification_report

# 1. Load the new, unseen dataset
# Adjust the filename to match whatever you named your new data
df_new = pd.read_csv("data/challenge_dataset.csv")

# Extract the text and the actual answers
X_new = df_new[['text']]
# This instantly translates the text into the 0s and 1s the AI uses
y_true = df_new['label'].map({"legitimate": 0, "phishing": 1})

# 2. Load your pre-trained AI model from the disk
# This loads the exact model that scored 99.8% earlier
model_path = "model/phishing_pipeline.joblib"
print(f"Loading trained model from {model_path}...")
pipeline = joblib.load(model_path)

# 3. Force the model to predict the new emails
print("Analyzing unseen emails...")
predictions = pipeline.predict(X_new)

# 4. Compare the AI's predictions to the real labels and print the results
print("\n--- GENERALIZATION TEST RESULTS ---")
report = classification_report(y_true, predictions, target_names=["legitimate", "phishing"])
print(report)