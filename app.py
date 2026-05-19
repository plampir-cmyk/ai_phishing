from __future__ import annotations

from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from feature_extraction import (
    compute_handcrafted_features,
    extract_content,
    get_header_anomalies,
    log_result,
    phishing_cues,
)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
MODEL_PATH = BASE_DIR / "model" / "phishing_pipeline.joblib"
LOG_PATH = BASE_DIR / "logs" / "analysis_log.csv"
ALLOWED_EXTENSIONS = {"html", "docx", "eml"}

app = Flask(__name__)
UPLOAD_FOLDER.mkdir(exist_ok=True)

pipeline = joblib.load(MODEL_PATH)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_risk(model_probability: float, cues: list[str], header_anomalies: list[str], feature_map: dict[str, float]) -> float:
    heuristic_score = min(
        1.0,
        (len(cues) * 0.07)
        + (len(header_anomalies) * 0.09)
        + (feature_map.get("suspicious_domain_count", 0) * 0.12)
        + (feature_map.get("ip_url_count", 0) * 0.15)
        + (feature_map.get("urgency_count", 0) * 0.04)
        + (feature_map.get("sensitive_count", 0) * 0.05)
        + (feature_map.get("url_shortener_count", 0) * 0.08),
    )
    return round(min(1.0, 0.68 * float(model_probability) + 0.32 * heuristic_score), 4)


def label_from_risk(risk: float) -> str:
    if risk >= 0.72:
        return "Likely phishing"
    if risk >= 0.45:
        return "Suspicious / needs review"
    return "Likely legitimate"


def risk_band(risk: float) -> str:
    if risk >= 0.72:
        return "high"
    if risk >= 0.45:
        return "medium"
    return "low"


@app.route("/", methods=["GET", "POST"])
def index():
    context = {
        "result": None,
        "risk_score": None,
        "model_probability": None,
        "cues": None,
        "header_anomalies": None,
        "features": None,
        "filename": None,
        "risk_percent": None,
        "risk_band": None,
    }
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            context["result"] = "No file was selected."
            return render_template("upload.html", **context)
        if not allowed_file(file.filename):
            context["result"] = "Unsupported file type. Use .html, .docx, or .eml"
            return render_template("upload.html", **context)

        filename = secure_filename(file.filename)
        path = UPLOAD_FOLDER / filename
        file.save(path)

        parsed = extract_content(str(path))
        text = parsed["text"]
        urls = parsed["urls"]
        headers = parsed["headers"]

        model_probability = float(pipeline.predict_proba(pd.DataFrame({"text": [text]}))[0][1])
        feature_map = compute_handcrafted_features(text, urls, headers)
        cues = phishing_cues(text, urls, headers)
        header_anomalies = get_header_anomalies(headers)
        risk_score = calculate_risk(model_probability, cues, header_anomalies, feature_map)
        result = label_from_risk(risk_score)

        log_result(
            str(LOG_PATH),
            {
                "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "filename": filename,
                "prediction": result,
                "risk_score": risk_score,
                "model_probability": round(model_probability, 4),
                "cue_count": len(cues),
                "header_anomaly_count": len(header_anomalies),
                "triggered_cues": "; ".join(cues),
            },
        )

        context.update(
            {
                "filename": filename,
                "result": result,
                "risk_score": risk_score,
                "risk_percent": int(round(risk_score * 100)),
                "risk_band": risk_band(risk_score),
                "model_probability": round(model_probability, 4),
                "cues": cues or ["No obvious phishing cues detected"],
                "header_anomalies": header_anomalies or ["No header anomalies detected"],
                "features": feature_map,
            }
        )
    return render_template("upload.html", **context)


if __name__ == "__main__":
    app.run(debug=True)
