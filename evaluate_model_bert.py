from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "challenge_dataset.csv"
MODEL_PATH = ROOT / "model" / "phishing_pipeline_bert.joblib"


def main() -> None:
    df = pd.read_csv(DATA_PATH)
    X = df[["text"]]
    y = (df["label"] == "phishing").astype(int)

    pipeline = joblib.load(MODEL_PATH)
    preds = pipeline.predict(X)
    probs = pipeline.predict_proba(X)[:, 1]

    print("Accuracy:", round(accuracy_score(y, preds), 4))
    print("Confusion matrix:")
    print(confusion_matrix(y, preds))
    print("\nClassification report:")
    print(classification_report(y, preds, target_names=["legitimate", "phishing"]))

    out = pd.DataFrame({
        "text": df["text"],
        "true_label": df["label"],
        "predicted_label": ["phishing" if p == 1 else "legitimate" for p in preds],
        "phishing_probability": probs,
    })
    out_path = ROOT / "logs" / "evaluation_predictions_bert.csv"
    out.to_csv(out_path, index=False)
    print(f"Saved detailed predictions to {out_path}")


if __name__ == "__main__":
    main()
