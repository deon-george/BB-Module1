# BB Extension Module 1 — URL Phishing Scanner

Offline, privacy-focused Chrome extension (Manifest V3) that scans every URL you load with a local XGBoost phishing model and blocks high-threat pages via a warning interstitial.

## Features
- Captures navigations with `webNavigation`, runs inference fully on-device.
- 111 lexical/structural URL features extracted in both Python (training) and JavaScript (extension) with identical names, order, and defaults.
- Local XGBoost inference (`inference.js`) reproduces `predict_proba` exactly.
- Configurable threat threshold (default 0.67) tuned on validation data.

