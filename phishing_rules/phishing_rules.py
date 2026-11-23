import ipaddress
import json
import os
import re

from urllib.parse import urlsplit, unquote
from email.utils import parseaddr

# Accessing domain_names.json for PHISH-003
HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "domain_names.json"), encoding="utf-8") as f:
    BRAND_DOMAINS = json.load(f)

# Since rules may flag emails without malware, they should be kept open for review
RESPONSE_CODES = {
    "High": ["PULL_EMAIL", "NOTIFY_ONCALL", "OPEN_TICKET"],
    "Medium": ["OPEN_TICKET"],
    "Low": [],
}


# PHISH-001
# Detect for emails requesting account credentials and verification
def check_credential_request(email):

    subject = email.get("subject") or ""
    body = email.get("body") or ""
    urls = email.get("urls") or []

    # Combine subject and body, then set all to lowercase for ease
    subject_body = (subject + " " + body).lower()

    # URL must be present for detection
    if not urls:
        return None

    # Common phrases that correlate to credential requests
    phrases = ["log into verify", "sign in to verify",
               "verify your account", "confirm your account",
               "enter your password", "re-enter your password",
               "reset your password", "update your password",
               "provide your password", "account verification", 
               "verify your identity"]

    # Check for suspicious phrases in email subject and body
    for phrase in phrases:
        if phrase in subject_body:
            return {
                "reason": f"Credential request ('{phrase}') with a URL",
                "count": 1
            }

    return None

# PHISH-002
# Detect for urgent/threatening messages that request 
# immediate action such as credential requests
def check_urgent_language(email):

    subject = email.get("subject") or ""
    body = email.get("body") or ""

    # Combine subject and body, then set all to lowercase for ease
    subject_body = (subject + " " + body).lower()

    # Common urgent/threatening phrases
    phrases_urgent = ["urgent", "immediate action",
                      "action required", "account locked",
                      "account suspended", "account will be suspended",
                      "unauthorized access", "unusual activity",
                      "lose access", "within 24 hours",
                      "within 12 hours", "final warning"]

    # Common phrases that request action
    phrases_action = ["click here", "click the link",
                      "verify your account", "verify your identity",
                      "confirm your account", "confirm your identity",
                      "sign in", "log in",
                      "update your information", "take action",
                      "act now", "reset your password"]

    # Check for both urgency and action request
    for urgent in phrases_urgent:
        if urgent in subject_body:
            for action in phrases_action:
                if action in subject_body:
                    return {
                        "reason": f"Urgent warning ('{urgent}') with action request ('{action}')",
                        "count": 1
                    }

    return None

# PHISH-003
# Detect for impersonation with sender domains
def check_sender_impersonation(email):

    from_name = (email.get("from_name") or "").lower()
    from_domain = (email.get("from_domain") or "").lower()

    # Skip emails without sender information
    if not from_name or not from_domain:
        return None

    from_name = " ".join(re.findall(r"[a-z0-9]+", from_name))

    ignored = ["www", "mail",
               "email", "login",
               "support", "secure",
               "service", "online",
               "com", "net"]

    matched_brands = []

    # Check organizations in dataset
    for organization, domains in BRAND_DOMAINS.items():

        # Remove common company suffixes
        brand_name = organization.lower()
        brand_name = re.sub(r"\b(inc|llc|ltd|limited|corporation|corp|gmbh)\b", "", brand_name)
        brand_name = " ".join(re.findall(r"[a-z0-9]+", brand_name))

        aliases = {brand_name}

        for domain in domains:
            label = domain.split(".")[0]
            alias = " ".join(re.findall(r"[a-z0-9]+", label.lower()))
            aliases.add(alias)

        # Check if display name claims to represent an organization
        for alias in aliases:
            if len(alias) < 3 or alias in ignored:
                continue
            if re.search(r"\b" + re.escape(alias) + r"\b", from_name):
                matched_brands.append((organization, domains))
                break

    if not matched_brands:
        return None

    # Accept any matching domain from identified organizations
    for organization, domains in matched_brands:
        for domain in domains:
            domain = domain.lower().strip(".")

            if from_domain == domain or from_domain.endswith("." + domain):
                return None

    # Claimed organization does not match sender's domain
    organization = matched_brands[0][0]

    return {
        "reason": f"Sender claims to be {organization} but uses domain {from_domain}",
        "count": 1
    }

# PHISH-004
# Detect suspicious URL domains
def check_suspicious_url_domain(email):

    from_domain = (email.get("from_domain") or "").lower().strip(".")
    url_domains = email.get("url_domains") or []

    subject = email.get("subject") or ""
    body = email.get("body") or ""
    text = (subject + " " + body).lower()

    if not from_domain or not url_domains:
        return None

    # Phrases related to sensitive account information
    phrases = ["verify your account", "confirm your account",
               "account verification", "update your billing information",
               "update your payment", "log in to your account",
               "sign in to your account", "verify your email"
               "verify your identity", "reset your password", 
               "update your password", "verify your account"]

    # Check for sensitive action request
    matched_phrase = None

    for phrase in phrases:
        if phrase in text:
            matched_phrase = phrase
            break

    if matched_phrase is None:
        return None

    # Check for difference between URL and sender domains
    for domain in url_domains:
        domain = domain.lower().strip(".")

        if (domain == from_domain 
            or domain.endswith("." + from_domain) 
            or from_domain.endswith("." + domain)):
            continue

        return {
            "reason": f"URL domain '{domain}' differs from sender domain '{from_domain}' during '{matched_phrase}' request",
            "count": 1
        }

    return None

# PHISH-005
# Detect URLs possibly hiding their destination
def check_obfuscated_urls(email):

    urls = email.get("urls") or []

    # Common URL shorteners
    shorteners = ["bit.ly", "tinyurl.com",
                  "t.co", "is.gd",
                  "ow.ly", "cutt.ly"
                  "rebrand.ly"]

    for url in urls:
        if not isinstance(url, str):
            continue

        # Separate domain from URL
        parsed = urlsplit(url if "://" in url else "https://" + url)
        domain = (parsed.hostname or "").lower()

        if not domain:
            continue

        # Check for shortened URLs
        if domain in shorteners:
            return {
                "reason": f"Shortened URL detected: {domain}",
                "count": 1
            }

        # Check for IP addresses replacing domain names
        try:
            ipaddress.ip_address(domain)
            return {
                "reason": f"IP address used in URL: {domain}",
                "count": 1
            }
        except ValueError:
            pass

        # Check for punycode domains
        if any(part.startswith("xn--") for part in domain.split(".")):
            return {
                "reason": f"Punycode domain detected: {domain}",
                "count": 1
            }

        # Check for encoded URLs possibly hiding another destination
        decoded_url = unquote(url)

        if decoded_url != url and "://" in decoded_url.split("?", 1)[-1]:
            return {
                "reason": f"Encoded URL destination detected: {url}",
                "count": 1
            }

    return None

# PHISH-006
# Detect suspicious login or account verification links
def check_suspicious_login_link(email):

    subject = email.get("subject") or ""
    body = email.get("body") or ""

    subject_body = (subject + " " + body).lower()

    from_domain = (email.get("from_domain") or "").lower().strip(".")
    urls = email.get("urls") or []

    if not from_domain or not urls:
        return None

    phrases_action = ["verify your account", "verify your identity",
                      "confirm your account", "sign in",
                      "log in", "reset your password",
                      "update your password"]

    if not any(phrase in subject_body for phrase in phrases_action):
        return None

    # Common keywords for login/verification URLs
    keywords_login = ["login", "log in",
                      "signin", "sign-in",
                      "sign in", "verify",
                      "verification", "password",
                      "authenticate", "authentication"]

    for url in urls:

        if not isinstance(url, str):
            continue

        parsed = urlsplit(url if "://" in url else "https://" + url)
        domain = (parsed.hostname or "").lower().strip(".")
        path = parsed.path.lower()

        if not domain:
            continue

        # Check if URL appears to be a login page
        if not any(word in domain or word in path for word in keywords_login):
            continue

        # Skip links using sender's domain or subdomains
        if (domain == from_domain
            or domain.endswith("." + from_domain)
            or from_domain.endswith("." + domain)):
            continue

        return {
            "reason": f"Suspicious login link '{domain} differs from sender domain '{from_domain}'",
            "count": 1
        }

    return None

# PHISH-007
# Detect authentication failures + phishing indicators
def check_authentication_failure(email):

    spf = (email.get("spf") or "").lower()
    dkim = (email.get("dkim") or "").lower()
    dmarc = (email.get("dmarc") or "").lower()

    failures = []
    indicators = []

    # Check for explicit authentication failures
    if spf in ["fail", "softfail"]:
        failures.append("SPF")
    if dkim =="fail":
        failures.append("DKIM")
    if dmarc == "fail":
        failures.append("DMARC")
    if not failures:
        return None

    # Check for phishing indicators
    if check_credential_request(email) is not None:
        indicators.append("Credential request")
    if check_urgent_language(email) is not None:
        indicators.append("Urgent language")
    if check_suspicious_login_link(email) is not None:
        indicators.append("Suspicious login link")

    if not indicators:
        return None

    return {
        "reason": f"Authentication failure ({', '.join(failures)}) with {', '.join(indicators)}",
        "count": len(failures) + len(indicators)
    }

    return None

# PHISH-008
# Detect suspicious difference between sender and reply addresses
def check_mismatched_addresses(email):

    from_domain = (email.get("from_domain") or "").lower().strip(".")
    reply_to = email.get("reply_to") or ""
    return_path_domain = (email.get("return_path_domain") or "").lower().strip(".")

    if not from_domain:
        return None

    # Check if email requests sensitive info
    subject = email.get("subject") or ""
    body = email.get("body") or ""

    subject_body = (subject + " " + body).lower()

    phrases_sensitive = ["verify your account", "confirm your account",
                         "provide your password", "send your information",
                         "update your payment", "update your password",
                         "payment details", "bank account details",
                         "wire transfer", "billing information"]

    if not any(phrase in subject_body for phrase in phrases_sensitive):
        return None

    # Check if two domains are related
    def check_matching_domains(domain):
        return (
            domain == from_domain or
                      domain.endswith("." + from_domain) or 
                      from_domain.endswith("." + domain)
        )

    mismatches = []

    reply_address = parseaddr(reply_to)[1]

    # Check Reply-To address
    if "@" in reply_address:
        reply_domain = reply_address.rsplit("@", 1)[1].lower().strip(".")

        if not check_matching_domains(reply_domain):
            mismatches.append(f"Reply-To domain: {reply_domain}")

    # Check Return-Path domain
    if return_path_domain and not check_matching_domains(return_path_domain):
        mismatches.append(f"Return-Path domain: {return_path_domain}")

    if mismatches:
        return {
            "reason": f"Sender domain '{from_domain}' differs from {', '.join(mismatches)}",
            "count": len(mismatches)
        }

    return None

# PHISH-009
# Detect potentially malicious attachments
def check_suspicious_attachment(email):

    attachments = email.get("attachments") or []
    subject = email.get("subject") or ""
    body = email.get("body") or ""

    subject_body = (subject + " " + body).lower()

    if not attachments:
        return None

    # File extensions that may be associated with malware/phishing
    suspicious_extensions = [".html", ".shtml",
                             ".zip", ".rar",
                             ".7z", ".exe",
                             ".bat", ".scr",
                             ".js", ".vbs",
                             ".docm", ".xlsm"]

    # Phrase that may indicate suspicious attachment requests
    suspicious_phrases = ["invoice", "payment",
                          "verify your account", "enter your password",
                          "open the attachment", "open the attached",
                          "view the attachment", "view the attached",
                          "enable macros", "enable content",
                          "billing information"]

    if not any(phrase in subject_body for phrase in suspicious_phrases):
        return None

    # Check each attachment
    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue

        filename = (attachment.get("filename") or "").lower()
        content_type = (attachment.get("content_type") or "").lower()

        # Check for suspicious file extensions
        if (any(filename.endswith(ext) for ext in suspicious_extensions) or
            content_type in ["text/html", "application/xhtml+xml"]):

            return {
                "reason": f"Suspicious attachment '{filename}' with phishing-related content",
                "count": 1
            }

    return None

# PHISH-010
# Detect suspicious payment/delivery/documetn requests
def check_payment_delivery_request(email):

    subject = email.get("subject") or ""
    body = email.get("body") or ""
    urls = email.get("urls") or []
    attachments = email.get("attachments") or []

    subject_body = (subject + " " + body).lower()

    # Common payment/delivery/document phrases
    phrases_request = ["unpaid invoice", "outstanding payment",
                       "payment overdue", "payment failed",
                       "update your billing", "update your payment",
                       "confirm your payment", "delivery failed",
                       "delivery attempt", "package on hold",
                       "shipment on hold", "confirm your delivery",
                       "view your document", "review the attached document",
                       "shared a document", "view the attached document"]

    # Common phrases requesting action
    phrases_action = ["click here", "click the link",
                      "open the attached", "open the attachment",
                      "download the file", "view the file",
                      "view the attached", "view the attachment",
                      "update your information", "provide your details",
                      "confirm your information", "take action"]

    # Check for suspicious requests and instructions
    matched_request = None
    matched_action = None

    for phrase in phrases_request:
        if phrase in subject_body:
            matched_request = phrase
            break
    for phrase in phrases_action:
        if phrase in subject_body:
            matched_action = phrase
            break

    if not matched_request or not matched_action:
        return None
    if not urls and not attachments:
        return None

    return {
        "reason": f"Suspicious request ('{matched_request}') with action ('{matched_action}')",
        "count": 1
    }

# PHISH-011
# Detect misleading sender addresses and suspicious domains
def check_deceptive_sender(email):

    from_name = email.get("from_name") or ""
    sender = email.get("from") or ""
    from_domain = (email.get("from_domain") or "").lower().strip(".")

    if not sender or not from_domain:
        return None

    # Extract actual sender email address
    sender_address = parseaddr(sender)[1].lower()

    # Check if display name contains different email address
    claimed_addresses = re.findall(r"[w\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", from_name)

    for address in claimed_addresses:
        if address.lower() != sender_address:
            return {
                "reason": f"Display name contains '{address}' while actual sender is '{sender_address}'",
                "count": 1
            }

    # Check for punycode domains
    if any(part.startswith("xn--") for part in from_domain.split(".")):
        return {
            "reason": f"Potentially deceptive sender domain: {from_domain}",
            "count": 1
        }

    return None

RULES = [
    {"id": "PHISH-001", "name": "Credential request", "severity": "High", "check": check_credential_request},
    {"id": "PHISH-002", "name": "Urgent language", "severity": "Medium", "check": check_urgent_language},
    {"id": "PHISH-003", "name": "Sender impersonation", "severity": "High", "check": check_sender_impersonation},
    {"id": "PHISH-004", "name": "Suspicious URL domain", "severity": "High", "check": check_suspicious_url_domain},
    {"id": "PHISH-005", "name": "Obfuscated URL", "severity": "Medium", "check": check_obfuscated_urls},
    {"id": "PHISH-006", "name": "Suspicious login link", "severity": "High", "check": check_suspicious_login_link},
    {"id": "PHISH-007", "name": "Authentication failure", "severity": "Medium", "check": check_authentication_failure},
    {"id": "PHISH-008", "name": "Mismatched email addresses", "severity": "Medium", "check": check_mismatched_addresses},
    {"id": "PHISH-009", "name": "Suspicious attachment", "severity": "Medium", "check": check_suspicious_attachment},
    {"id": "PHISH-010", "name": "Payment or delivery request", "severity": "Medium", "check": check_payment_delivery_request},
    {"id": "PHISH-011", "name": "Deceptive sender information", "severity": "Medium", "check": check_deceptive_sender}
]