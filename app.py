import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

ANAKIN_API_KEY = os.environ.get("ANAKIN_API_KEY", "")
WIRE_URL       = "https://anakin.io/v1/holocron/task"
SEARCH_URL     = "https://api.anakin.io/v1/search"
HEADERS        = {"X-API-Key": ANAKIN_API_KEY, "Content-Type": "application/json"}

SCAM_SIGNALS    = ["scam","fraud","fake","phishing","malware","spam","beware","warning",
                   "reported","dangerous","unsafe","blocked","not legit","avoid","suspicious",
                   "do not click","identity theft","ponzi","illegal","scammer","reported fraud"]
SAFE_SIGNALS    = ["legitimate","verified","trusted","official","authorized","secure",
                   "safe","reliable","certified","reputable"]
URGENCY_WORDS   = ["act now","limited time","expires","hurry","only today","last chance",
                   "24 hours","immediately","don't wait","act fast","claim now","running out"]
SUSPICIOUS_TLDS = ["xyz","tk","ml","ga","cf","gq","click","loan","win","prize","buzz","top"]
SHORTENERS      = ["bit.ly","tinyurl","t.co","goo.gl","ow.ly","rb.gy","cutt.ly"]


def scrape_with_wire(url):
    """Step 1: Wire scrapes the live page and returns clean text."""
    try:
        r = requests.post(WIRE_URL,
            json={"action_id": "ap_article", "params": {"url": url}},
            headers=HEADERS, timeout=12)
        if r.status_code == 200:
            d = r.json()
            text = (d.get("data", {}).get("text") or
                    d.get("data", {}).get("content") or
                    d.get("data", {}).get("markdown") or
                    d.get("result", {}).get("text") or "")
            print(f"[Wire] {len(text)} chars scraped")
            return text[:4000]
    except Exception as e:
        print(f"[Wire error] {e}")
    return None


def check_reputation(url, mode):
    """Step 2: Anakin Search API checks domain reputation on the web."""
    try:
        if mode == "text":
            query = f"scam fraud: {url[:150]}"
        else:
            domain = re.sub(r'https?://', '', url).split('/')[0]
            query  = f'is "{domain}" a scam or legitimate site'
        r = requests.post(SEARCH_URL,
            json={"prompt": query, "limit": 5},
            headers=HEADERS, timeout=12)
        if r.status_code == 200:
            results = r.json().get("results", [])
            combined = " ".join(
                f"{x.get('title','')} {x.get('snippet','')}" for x in results
            ).lower()
            print(f"[Search API] {len(results)} results")
            return combined
    except Exception as e:
        print(f"[Search API error] {e}")
    return None


def analyse_with_wire_ai(content_text, target, mode):
    """
    Step 3: Pass scraped content BACK to Wire AI for deep threat analysis.
    Wire acts as the AI brain — it reads the page content and gives a structured
    fraud assessment. This is where Wire goes beyond scraping into intelligence.
    Workflow unchanged: Wire scrapes first, then Wire AI analyses.
    """
    try:
        system_prompt = (
            "You are a cybersecurity fraud analyst AI. Analyse the provided web page content or message "
            "for scam and fraud signals. Respond ONLY with a valid JSON object, no extra text:\n"
            "{\n"
            '  "ai_scam_detected": true/false,\n'
            '  "ai_confidence": 0-100,\n'
            '  "ai_scam_type": "string (e.g. Phishing, Financial Fraud, Brand Impersonation, Safe)",\n'
            '  "ai_reason": "1-2 sentence plain English explanation",\n'
            '  "ai_flags": ["flag1", "flag2"] // max 3 specific red flags found, empty array if safe\n'
            "}\n"
            "Be strict. Fake urgency, brand impersonation, impossible offers, OTP requests = scam signals."
        )

        user_message = (
            f"Target: {target}\nMode: {mode}\n\n"
            f"Page content to analyse:\n{content_text[:3000]}"
        )

        r = requests.post(WIRE_URL,
            json={
                "action_id": "ap_chat",
                "params": {
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_message}]
                }
            },
            headers=HEADERS, timeout=20)

        if r.status_code == 200:
            d = r.json()
            raw = (d.get("data", {}).get("text") or
                   d.get("data", {}).get("content") or
                   d.get("result", {}).get("text") or "")
            # Strip markdown fences if present
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            import json
            parsed = json.loads(raw)
            print(f"[Wire AI] confidence={parsed.get('ai_confidence')} scam={parsed.get('ai_scam_detected')}")
            return parsed
    except Exception as e:
        print(f"[Wire AI error] {e}")
    return None


def build_verdict(url, page_text, reputation_text, wire_ai_result, mode):
    """
    Final verdict: combines URL signals + Search API reputation + Wire AI analysis.
    Wire AI result gets highest weight when available.
    """
    score   = 100
    flags   = []
    url_low = url.lower()
    has_urgency = False

    # ── URL-level signals ──────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if f".{tld}" in url_low:
            flags.append({"label": f"Suspicious TLD (.{tld})", "type": "threat"})
            score -= 25; break

    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
        flags.append({"label": "IP address instead of domain", "type": "threat"})
        score -= 35

    if any(s in url_low for s in SHORTENERS):
        flags.append({"label": "URL shortener — destination hidden", "type": "threat"})
        score -= 20

    if mode == "url" and not url_low.startswith("https://"):
        flags.append({"label": "No HTTPS — unsecured connection", "type": "threat"})
        score -= 15

    # ── Anakin Search API reputation signals ──────────────────────────────
    if reputation_text:
        scam_hits = [w for w in SCAM_SIGNALS if w in reputation_text]
        safe_hits = [w for w in SAFE_SIGNALS if w in reputation_text]
        if len(scam_hits) >= 3:
            flags.append({"label": f"Multiple scam reports online: {', '.join(scam_hits[:3])}", "type": "threat"})
            score -= 40
        elif len(scam_hits) >= 1:
            flags.append({"label": f"Scam mentions found: {', '.join(scam_hits[:2])}", "type": "threat"})
            score -= 20
        if len(safe_hits) >= 2:
            flags.append({"label": "Positive reputation signals found", "type": "safe"})
            score += 10
        flags.append({"label": "Domain reputation checked via Anakin Search API", "type": "safe"})

    # ── Wire AI deep content analysis (highest weight) ────────────────────
    ai_reason_override = None
    ai_scam_type_override = None

    if wire_ai_result:
        ai_confidence = wire_ai_result.get("ai_confidence", 50)
        ai_scam_detected = wire_ai_result.get("ai_scam_detected", False)
        ai_reason_override = wire_ai_result.get("ai_reason", "")
        ai_scam_type_override = wire_ai_result.get("ai_scam_type", "")
        ai_flags = wire_ai_result.get("ai_flags", [])

        if ai_scam_detected:
            # Wire AI says scam — apply weighted penalty based on confidence
            penalty = int((ai_confidence / 100) * 50)
            score -= penalty
            for af in ai_flags[:3]:
                flags.append({"label": f"Wire AI: {af}", "type": "threat"})
            flags.append({"label": f"Wire AI threat confidence: {ai_confidence}%", "type": "threat"})
        else:
            # Wire AI says safe — boost score
            bonus = int((ai_confidence / 100) * 20)
            score += bonus
            flags.append({"label": f"Wire AI: No fraud patterns detected ({ai_confidence}% confidence)", "type": "safe"})

        # Check urgency in AI flags
        if any("urgency" in f.lower() or "urgent" in f.lower() for f in ai_flags):
            has_urgency = True

    # ── Fallback: keyword scan on page text if Wire AI unavailable ─────────
    elif page_text or (mode == "text"):
        check_text = page_text if page_text else url
        pl = check_text.lower()
        u_hits = [w for w in URGENCY_WORDS if w in pl]
        if u_hits:
            flags.append({"label": f'Fake urgency detected: "{u_hits[0]}"', "type": "threat"})
            score -= 30; has_urgency = True

        brands = ["apple","amazon","google","microsoft","paypal","hdfc","sbi","icici","paytm","whatsapp","flipkart"]
        b_hits = [b for b in brands if b in pl]
        if b_hits and any(a in pl for a in ["verify","login","confirm","update","click here","suspended","blocked"]):
            flags.append({"label": f"Brand impersonation: {b_hits[0].upper()}", "type": "threat"})
            score -= 40

        crypto = ["guaranteed returns","double your money","100% profit","risk-free investment","bitcoin profit"]
        c_hits = [c for c in crypto if c in pl]
        if c_hits:
            flags.append({"label": f'Financial fraud language: "{c_hits[0]}"', "type": "threat"})
            score -= 30

        text_scam = ["account suspended","account blocked","verify your","otp","password reset",
                     "click here to verify","permanently blocked","act now","claim now","you have won",
                     "your account","won a prize","congratulations you","free gift","urgent"]
        t_hits = [t for t in text_scam if t in pl]
        if len(t_hits) >= 2:
            flags.append({"label": f'Multiple scam phrases: "{t_hits[0]}", "{t_hits[1]}"', "type": "threat"})
            score -= 30
        elif len(t_hits) == 1:
            flags.append({"label": f'Scam phrase detected: "{t_hits[0]}"', "type": "threat"})
            score -= 15

        if mode == "text":
            flags.append({"label": "Ad copy analyzed for scam signals", "type": "safe"})
        else:
            flags.append({"label": "Page content extracted via Anakin Wire", "type": "safe"})

    if not any(f["type"] == "threat" for f in flags):
        flags.append({"label": "No scam patterns detected", "type": "safe"})
        flags.append({"label": "Domain appears clean", "type": "safe"})

    score = max(0, min(100, score))

    # ── Final verdict ──────────────────────────────────────────────────────
    if score < 35:
        risk, is_scam = "high", True
        stype  = ai_scam_type_override or "Phishing / Suspicious Ad"
        reason = ai_reason_override or "Multiple high-risk fraud signals detected across URL, page content, and web reputation."
    elif score < 65:
        risk, is_scam = "medium", False
        stype  = ai_scam_type_override or "Suspicious — Needs Caution"
        reason = ai_reason_override or "Some suspicious signals detected. Avoid sharing personal information."
    else:
        risk, is_scam = "low", False
        stype  = ai_scam_type_override or "Verified Safe"
        reason = ai_reason_override or "No significant threats detected. URL, content, and reputation appear legitimate."

    if has_urgency:
        reason += " Fake urgency manipulation tactics also detected."

    complaint = ""
    if is_scam:
        complaint = (
            f"Dear Cyber Crime Cell,\n\nI wish to report a fraudulent link: {url}\n\n"
            f"ScamShield AI (Anakin Wire + Search API) flagged this as: {stype}.\n"
            f"Signals: phishing patterns{', fake urgency' if has_urgency else ''}.\n\n"
            f"Please investigate and take action.\n\nThank you."
        )

    return {
        "trust_score": score, "risk_level": risk, "is_scam": is_scam,
        "scam_type": stype, "reason": reason,
        "fake_urgency_detected": has_urgency,
        "flags": flags[:6], "cyber_complaint_draft": complaint
    }


@app.route('/')
def home():
    return send_from_directory('.', 'homepage.html')

@app.route('/Styles.css')
def styles():
    return send_from_directory('.', 'Styles.css')


@app.route('/scan', methods=['POST'])
def scan_link():
    try:
        body   = request.json or {}
        target = body.get('url', '').strip()
        mode   = body.get('mode', 'url')

        if not target:
            return jsonify({"error": "No input provided"}), 400

        page_text    = None
        rep_text     = None
        wire_ai_result = None

        # ── Step 1 & 2: Wire scrape + Search API run in PARALLEL ──────────
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {}
            if mode == 'url':
                futures['wire'] = executor.submit(scrape_with_wire, target)
            futures['search'] = executor.submit(check_reputation, target, mode)

            for key, future in futures.items():
                try:
                    result = future.result(timeout=15)
                    if key == 'wire':
                        page_text = result
                    elif key == 'search':
                        rep_text  = result
                except Exception as e:
                    print(f"[{key} future error] {e}")

        # ── Step 3: Wire AI analyses the scraped content ──────────────────
        content_for_ai = page_text if page_text else (target if mode == "text" else None)
        if content_for_ai:
            wire_ai_result = analyse_with_wire_ai(content_for_ai, target, mode)

        # ── Step 4: Build final verdict ───────────────────────────────────
        verdict = build_verdict(target, page_text, rep_text, wire_ai_result, mode)
        print(f"[Done] Score={verdict['trust_score']} Risk={verdict['risk_level']}")
        return jsonify(verdict)

    except Exception as e:
        return jsonify({"error": "Engine error", "details": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True, port=5000)
