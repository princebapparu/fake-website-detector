import streamlit as st
from urllib.parse import urlparse
import requests
import socket
import ssl
from datetime import datetime
import whois
import re

st.set_page_config(
    page_title="Fake Website Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Fake Website Detector")
st.write("Paste a website URL below to check if it looks legitimate or potentially phishing.")

url = st.text_input("Enter Website URL")

def analyze_url(url):
    score = 100
    reasons = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # HTTPS Check
    if parsed.scheme != "https":
        score -= 20
        reasons.append("Website does not use HTTPS.")
    else:
        reasons.append("HTTPS detected.")

    # Suspicious words
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "banking",
        "confirm",
        "wallet",
        "password"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score -= 5
            reasons.append(f"Suspicious keyword detected: '{word}'")

    # Too many special characters
    special_count = len(re.findall(r'[-@_=]', domain))
    if special_count >= 3:
        score -= 15
        reasons.append("Too many special characters in domain.")

    # Long URL
    if len(url) > 75:
        score -= 10
        reasons.append("URL is unusually long.")

    # IP Address instead of domain
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(ip_pattern, domain):
        score -= 25
        reasons.append("Website uses IP address instead of domain name.")

    # WHOIS domain age
    try:
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days

            if age_days < 30:
                score -= 30
                reasons.append(f"Domain is very new ({age_days} days old).")

            elif age_days < 180:
                score -= 15
                reasons.append(f"Domain is relatively new ({age_days} days old).")

            else:
                reasons.append(f"Domain age: {age_days} days.")

    except:
        score -= 10
        reasons.append("Could not verify domain age.")

    # SSL Certificate Check
    try:
        hostname = domain

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                pass

        reasons.append("Valid SSL certificate detected.")

    except:
        score -= 15
        reasons.append("SSL certificate validation failed.")

    # Website Reachability
    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            reasons.append("Website is reachable.")
        else:
            score -= 5
            reasons.append(
                f"Website returned unusual status code: {response.status_code}"
            )

    except:
        score -= 10
        reasons.append("Website could not be reached.")

    score = max(0, min(score, 100))

    if score >= 70:
        verdict = "SAFE / LEGITIMATE"
    else:
        verdict = "FAKE / PHISHING RISK"

    return verdict, score, reasons


if st.button("Analyze Website"):

    if not url:
        st.warning("Please enter a URL.")
    else:

        with st.spinner("Analyzing website..."):
            verdict, score, reasons = analyze_url(url)

        st.subheader("Result")

        if score >= 70:
            st.success(f"{verdict}")
        else:
            st.error(f"{verdict}")

        st.metric("Confidence Score", f"{score}%")

        st.subheader("Analysis Details")

        for item in reasons:
            st.write("•", item)

        st.info(
            "This tool uses heuristic analysis and should not be considered a replacement for professional cybersecurity solutions."
        )