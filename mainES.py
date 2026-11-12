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
            link_security = "[ALERTA DE SEGURIDAD] El enlace puede ser INSEGURO, recomendamos no abrirlo."
            risk += 5
        else:
            link_security = "El enlace usa extensiones estándar, pero se recomienda precaución."
            risk += 1
    else:
        link_security = "El mensaje no contiene ningún enlace."

    if risk >= 8:
        risk_evaluation = "MUY INSEGURO."
    elif risk >= 5:
        risk_evaluation = "INSEGURO."
    elif risk >= 2:
        risk_evaluation = "Sospechoso."
    else:
        risk_evaluation = "Seguro, pero recomendamos tener cuidado."

    final_diagnostic = f"""
    ------- DIAGNÓSTICO -------
    Señales sospechosas detectadas: {signals}
    ¿El mensaje tiene un enlace? {link_verification}
    Estado de seguridad del enlace: {link_security}
    Evaluación final de riesgo: {risk_evaluation} (Puntuación: {risk})"""

    print(final_diagnostic)

message = input("¡Hola, bienvenido al sistema PhishCheckU, por favor, introduce el mensaje sospechoso aquí: ")
analizeMessage(message)