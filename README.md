# 🛡️ ScamShield AI — Ad & Link Fraud Detector

**Built by Shubham Bhavar**

ScamShield AI is a real-time fraud detection tool that helps users identify scam links, fake ads, and suspicious messages before they become victims. Powered by Anakin Wire + Search API, it analyses URLs and ad copy for phishing, brand impersonation, fake urgency, and other fraud signals — and generates a ready-to-file cyber cell complaint if a threat is detected.

---

## ✨ Features

- 🔗 **Scan ad URLs** — Paste any sponsored link or domain for instant fraud analysis
- 📝 **Scan ad copy / SMS** — Paste suspicious text messages or ad copy for scam signal detection
- 📊 **Trust Score** — Get a 0–100 safety score with plain-language explanation
- 🚨 **Fake Urgency Detection** — Identifies manipulation tactics like "Act now" or "Limited time"
- 📋 **Cyber Cell Complaint Generator** — Auto-drafts a complaint ready to file with authorities
- 📣 **WhatsApp Alert Broadcast** — Share scan results instantly with family and friends
- 🌗 **Dark / Light Mode** — Clean UI with theme toggle
- 📈 **Scan Dashboard** — Track your scan history and threat statistics in session

---

## 🛠️ Tech Stack

- **Backend** — Python, Flask, Gunicorn
- **AI & Scraping** — Anakin Wire (Universal Scraper + AI Chat)
- **Web Intelligence** — Anakin Search API
- **Frontend** — HTML, CSS, Vanilla JavaScript
- **Deployment** — Railway

---

## 🚀 Deployment

This project is deployed on [Railway](https://railway.app).

### Environment Variables

| Variable | Description |
|---|---|
| `ANAKIN_API_KEY` | Your Anakin API key |

---

## 📁 Project Structure

```
├── app.py           # Flask backend — scan engine
├── homepage.html    # Frontend UI
├── Styles.css       # Stylesheet
├── railway.json     # Railway deployment config
└── .env             # Environment variables (local only)
```

---

## ⚠️ Disclaimer

ScamShield AI is built for public awareness and safety. It is not a substitute for professional cybersecurity advice. Always report scams to your local cyber crime cell at [cybercrime.gov.in](https://cybercrime.gov.in).

---

*ScamShield AI — Anakin Blitz V2 · Built for public safety by Shubham Bhavar*
