from __future__ import annotations

import json
import os
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from feature_extraction import build_numeric_feature_frame

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DEFAULT_DATASET = DATA_DIR / "dataset_large.csv"
MODEL_DIR = ROOT / "model"


def build_pipeline() -> Pipeline:
    text_features = TfidfVectorizer(ngram_range=(1, 2), min_df=2, stop_words="english")
    numeric_features = FunctionTransformer(build_numeric_feature_frame, validate=False)

    preprocessor = ColumnTransformer(
        transformers=[
            ("text", text_features, "text"),
            ("numeric", numeric_features, "text"),
        ]
    )

    model = LogisticRegression(max_iter=1200, class_weight="balanced")
    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", model),
    ])


def main() -> None:
    dataset_name = os.environ.get("PHISHING_DATASET", "dataset_large.csv")
    data_path = DATA_DIR / dataset_name
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    df = pd.read_csv(data_path)
    X = df[["text"]]
    y = (df["label"] == "phishing").astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    preds = pipeline.predict(X_test)
    report = classification_report(y_test, preds, target_names=["legitimate", "phishing"], output_dict=True)

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(pipeline, MODEL_DIR / "phishing_pipeline.joblib")
    with open(MODEL_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump({"dataset": dataset_name, "rows": len(df), "report": report}, f, indent=2)

    print("Dataset:", data_path)
    print("Rows:", len(df))
    print("Model saved to", MODEL_DIR / "phishing_pipeline.joblib")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
