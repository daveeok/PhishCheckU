def analizeMessage(message):
    suspiciousWords = ["verification", "verify", "suspended", "link", "24", "hours", "hacked", "hack", "recover", "login"]

    credentials = ["password", "user", "pin", "code", "credit", "debit"]

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
                linkSecurity = "The link may be secure, but we recommend review it."
        for extension in suspiciousLinkExtensions:
            if extension in message:
                linkSecurity = "[SECURITY WARN] The link may be INSECURE, we recommend don't open it."
                risk += 3
    if linkVerification == False:
        linkSecurity = "The link doesn't exist."
    if risk > 10:
        riskEvaluation = "VERY INSECURE."
    elif risk > 5:
        riskEvaluation = "INSECURE."
    elif risk > 1:
        riskEvaluation = "Suspicious."
    elif risk < 1:
        riskEvaluation = "Secure, But we recommed to be careful."

    finalDiagnostic = f"""
    ------- DIAGNOSTIC -------
    Suspicious signals in this message: {signals}
    The message has a link? {linkVerification}
    Is the link secure? {linkSecurity}
    The message is {riskEvaluation}"""

    print(finalDiagnostic)



message = input("¡Hello, welcome to the PhishCheckU system, please, put the suspicious message here: ").lower()

analizeMessage(message)

