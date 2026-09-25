import streamlit as st
import re
from urllib.parse import urlparse
from datetime import datetime

# ---------------- PAGE CONFIG ----------------

st.set_page_config(
    page_title="PhishShield AI",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- SESSION STATE ----------------

if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- CUSTOM CSS ----------------

st.markdown("""
<style>

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

.title {
    font-size: 45px;
    font-weight: 800;
}

.subtitle {
    font-size: 20px;
    margin-bottom: 10px;
}

.student-card {
    padding: 18px;
    border-radius: 15px;
    border: 1px solid rgba(128,128,128,0.3);
    margin: 20px 0;
}

</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------

st.markdown(
    '<div class="title">🛡️ PhishShield AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'On-Device Phishing & Scam Detection'
    '</div>',
    unsafe_allow_html=True
)

st.markdown("""
<div class="student-card">

### 👨‍💻 Project Presented By

**Anshuman Dash**

</div>
""", unsafe_allow_html=True)

st.write(
    "A local-first cybersecurity prototype that analyzes "
    "messages and URLs for suspicious threat signals."
)

st.divider()

# ---------------- DETECTION ENGINE ----------------

def analyze_input(text):

    text_lower = text.lower()

    score = 0
    signals = []

    # ---------- URGENCY ----------

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "hurry",
        "expires",
        "within 10 minutes",
        "within 24 hours",
        "last chance",
        "account will be blocked",
        "account will be suspended"
    ]

    if any(word in text_lower for word in urgency_words):
        score += 20
        signals.append(
            "⚠️ Urgent or threatening language detected"
        )

    # ---------- SENSITIVE INFORMATION ----------

    sensitive_words = [
        "password",
        "otp",
        "pin",
        "cvv",
        "card number",
        "bank details",
        "login credentials",
        "verification code"
    ]

    if any(word in text_lower for word in sensitive_words):
        score += 30
        signals.append(
            "🔐 Request for sensitive information detected"
        )

    # ---------- FINANCIAL CONTENT ----------

    financial_words = [
        "payment",
        "pay now",
        "transfer money",
        "bank account",
        "investment",
        "refund",
        "prize",
        "lottery",
        "reward",
        "cash"
    ]

    if any(word in text_lower for word in financial_words):
        score += 20
        signals.append(
            "💰 Financial or reward-related request detected"
        )

    # ---------- URL ANALYSIS ----------

    urls = re.findall(
        r'https?://[^\s]+',
        text
    )

    for url in urls:

        score += 10

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # IP address URL

        if re.match(
            r'^(\d{1,3}\.){3}\d{1,3}$',
            domain.split(":")[0]
        ):
            score += 25

            signals.append(
                "🌐 URL uses an IP address instead of a normal domain"
            )

        # HTTP instead of HTTPS

        if parsed.scheme == "http":

            score += 10

            signals.append(
                "🔓 Website does not use HTTPS"
            )

        # Very long URL

        if len(url) > 100:

            score += 10

            signals.append(
                "🔎 Unusually long URL detected"
            )

        # Too many subdomains

        if domain.count(".") >= 3:

            score += 10

            signals.append(
                "🌐 Unusual number of subdomains detected"
            )

        # Suspicious URL keywords

        suspicious_url_words = [
            "login",
            "verify",
            "secure",
            "update",
            "account",
            "claim",
            "winner",
            "free"
        ]

        if any(
            word in domain
            for word in suspicious_url_words
        ):

            score += 10

            signals.append(
                "🚨 Suspicious keywords found in URL"
            )

    # ---------- SCAM PATTERNS ----------

    scam_patterns = [
        "you won",
        "you have won",
        "free gift",
        "fake job",
        "work from home",
        "customer support",
        "click here",
        "verify your account",
        "claim your reward"
    ]

    if any(
        pattern in text_lower
        for pattern in scam_patterns
    ):

        score += 20

        signals.append(
            "🚨 Possible phishing/scam pattern detected"
        )

    # ---------- LIMIT SCORE ----------

    score = min(score, 100)

    # ---------- CLASSIFICATION ----------

    if score >= 60:

        level = "HIGH RISK"
        icon = "🔴"
        action = "BLOCK / AVOID"

    elif score >= 30:

        level = "SUSPICIOUS"
        icon = "🟡"
        action = "WARN USER"

    else:

        level = "LOW RISK"
        icon = "🟢"
        action = "ALLOW"

    # ---------- NO SIGNALS ----------

    if not signals:

        signals.append(
            "✅ No major suspicious signals detected"
        )

    return score, level, icon, action, signals


# ---------------- THREAT SCANNER ----------------

st.subheader("🔍 Threat Scanner")

scan_type = st.selectbox(
    "Select scan type",
    [
        "Message / SMS",
        "URL",
        "Email"
    ]
)

user_input = st.text_area(
    "Enter the content you want to analyze",
    height=180,
    placeholder=(
        "Example:\n"
        "URGENT! Your bank account will be blocked. "
        "Click https://example.com to verify your OTP."
    )
)

# ---------------- SCAN BUTTON ----------------

if st.button(
    "🔎 SCAN FOR THREATS",
    use_container_width=True
):

    if not user_input.strip():

        st.warning(
            "Please enter a message or URL first."
        )

    else:

        score, level, icon, action, signals = analyze_input(
            user_input
        )

        # Save scan history

        st.session_state.history.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": scan_type,
            "score": score,
            "result": level
        })

        st.divider()

        # ---------------- RESULT ----------------

        st.subheader("📊 Analysis Result")

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Risk Score",
                f"{score}/100"
            )

        with col2:

            st.metric(
                "Threat Level",
                level
            )

        with col3:

            st.metric(
                "Recommended Action",
                action
            )

        # ---------------- STATUS ----------------

        if score >= 60:

            st.error(
                f"{icon} {level} — Possible phishing / scam"
            )

        elif score >= 30:

            st.warning(
                f"{icon} {level}"
            )

        else:

            st.success(
                f"{icon} {level}"
            )

        # ---------------- SIGNALS ----------------

        st.subheader("🔎 Detected Threat Signals")

        for signal in signals:

            st.write(signal)

        # ---------------- RECOMMENDATION ----------------

        st.subheader("💡 Safety Recommendation")

        if score >= 60:

            st.write(
                "Do not click suspicious links or provide "
                "passwords, OTPs, PINs or payment information."
            )

        elif score >= 30:

            st.write(
                "Be careful. Verify the sender and website "
                "through an official source before taking action."
            )

        else:

            st.write(
                "No major threat signals were detected, "
                "but always verify unexpected messages."
            )


# ---------------- SCAN HISTORY ----------------

st.divider()

st.subheader("📜 Scan History")

if st.session_state.history:

    for item in reversed(
        st.session_state.history[-10:]
    ):

        st.write(
            f"**{item['time']}** | "
            f"{item['type']} | "
            f"Risk: **{item['score']}/100** | "
            f"{item['result']}"
        )

else:

    st.info(
        "No scans performed yet."
    )


# ---------------- ABOUT PROJECT ----------------

st.divider()

st.subheader("ℹ️ About PhishShield AI")

st.write(
    "**PhishShield AI** is an educational cybersecurity "
    "prototype designed to demonstrate local-first "
    "phishing and scam detection."
)

st.write(
    "The system analyzes suspicious signals from "
    "messages and URLs and produces an explainable "
    "risk score."
)

st.write(
    "**Project Presented By: Anshuman Dash**"
)

# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "PhishShield AI v1 • Educational Cybersecurity Prototype • "
    "Local-First Threat Analysis"
        )
