import re
from urllib.parse import urlparse

def analizeMessage(message):
    message_lower = message.lower()
    
    urgency_words = ["suspended", "24", "hours", "hacked", "hack", "urgent", "immediately", "expired"]
    action_words = ["verification", "verify", "recover", "login", "update", "validate"]
    credential_words = ["password", "user", "pin", "code", "credit", "debit", "ssn", "cvv"]
    
    suspicious_link_extensions = [
        ".xyz", ".top", ".click", ".icu", ".buzz", ".cyou", 
        ".sbs", ".cfd", ".zip", ".mov", ".tk", ".ml", ".ga"
    ]
    
    signals = []
    risk = 0
    link_verification = False
    link_security = ""
    
    for word in urgency_words:
        if word in message_lower:
            risk += 1
            signals.append(f"Urgencia: '{word}'")
            
    for word in action_words:
        if word in message_lower:
            risk += 2
            signals.append(f"Acción sospechosa: '{word}'")
            
    for word in credential_words:
        if word in message_lower:
            risk += 3
            signals.append(f"Credencial solicitada: '{word}'")

    urls = re.findall(r'https?://[^\s]+', message)
    
    if urls:
        link_verification = True
        insecure_found = False
        
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            for ext in suspicious_link_extensions:
                if domain.endswith(ext) or ext in domain:
                    insecure_found = True
                    signals.append(f"Dominio sospechoso detectado: {domain}")
                    
        if insecure_found:
            link_security = "[SECURITY WARN] The link may be INSECURE, we recommend don't open it."
            risk += 5
        else:
            link_security = "The link uses standard extensions, but caution is advised."
            risk += 1
    else:
        link_security = "The message doesn't contain a link."

    if risk >= 8:
        risk_evaluation = "VERY INSECURE."
    elif risk >= 5:
        risk_evaluation = "INSECURE."
    elif risk >= 2:
        risk_evaluation = "Suspicious."
    else:
        risk_evaluation = "Secure, but we recommend to be careful."

    final_diagnostic = f"""
    ------- DIAGNOSTIC -------
    Suspicious signals detected: {signals}
    The message has a link? {link_verification}
    Link security status: {link_security}
    Final Risk Evaluation: {risk_evaluation} (Score: {risk})"""

    print(final_diagnostic)

message = input("¡Hello, welcome to the PhishCheckU system, please, put the suspicious message here: ")
analizeMessage(message)