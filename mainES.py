def analizeMessage(message):
    suspiciousWords = ["verificación", "verificar", "suspendición", "suspendida", "enlace", "link", "24", "horas", "hackeada", "hackeo", "recuperar", "sesión"]

    credentials = ["contraseña", "usuario", "pin", "código", "crédito", "débito"]

    linkNormalExtensions = [".com", ".es", ".co", ".mx", ".us", ".edu", ".gov", ".edu.co", "gov.co", ".us"]

    suspiciousLinkExtensions = [".xyz", ".top", ".click", ".icu", ".buzz,", ".cyou", ".sbs", ".cfd", ".zip", ".mov"]

    linkVerification = False

    linkSecurity = ""

    signals = []

    risk = 0

    riskEvaluation = ""

    for word in suspiciousWords:
        if word in message:
            risk += 1
            signals.append(word)
    for word in credentials:
        if word in message:
            risk += 1
            signals.append(word)

    if "http" in message:
        linkVerification = True
        for extension in linkNormalExtensions:
            if extension in message:
                linkSecurity = "El enlace podría ser seguro, pero recomendamos revisarlo."
        for extension in suspiciousLinkExtensions:
            if extension in message:
                linkSecurity = "[ALERTA DE SEGURIDAD] El enlace podría ser INSEGURO, recomendamos no abrirlo."
                risk += 3
    if linkVerification == False:
        linkSecurity = "El mensaje no contiene ningún enlace."
    if risk > 10:
        riskEvaluation = "MUY INSEGURO."
    elif risk > 5:
        riskEvaluation = "INSEGURO."
    elif risk > 1:
        riskEvaluation = "Sospechoso."
    elif risk < 1:
        riskEvaluation = "Seguro, pero recomendamos tener cuidado."

    finalDiagnostic = f"""
    ------- DIAGNÓSTICO -------
    Señales sospechosas en este mensaje: {signals}
    ¿El mensaje tiene un enlace? {linkVerification}
    ¿El enlace es seguro? {linkSecurity}
    El mensaje es {riskEvaluation}"""

    print(finalDiagnostic)



message = input("¡Hola, bienvenido al sistema PhishCheckU! Por favor, pega aquí el mensaje sospechoso: ").lower()

analizeMessage(message)