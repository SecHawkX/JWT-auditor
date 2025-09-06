import os
import jwt
import base64
import json
import datetime
from flask import Flask, render_template, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT

app = Flask(__name__)

# Allowed algorithms
ALLOWED_ALGOS = [
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "EdDSA"
]

def base64url_decode(input_str):
    """Decode base64url safely"""
    if not input_str:
        return b""
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

def weak_secret_key_check(token, wordlist="scraped-JWT-secrets.txt"):
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        return f"Could not parse JWT header: {e}"

    algo = header.get("alg", "HS256")

    if not algo.startswith("HS"):
        return f"{algo} is not HMAC. Skipping brute-force."

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for secret in f:
                secret = secret.strip()
                if not secret:
                    continue
                try:
                    decoded = jwt.decode(token, secret, algorithms=[algo], options={"verify_exp": False})
                    return f"✅ Found secret: {secret}<br><pre>{json.dumps(decoded, indent=4)}</pre>"
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
    except FileNotFoundError:
        return f"Wordlist not found: {wordlist}"

    return "❌ No weak secret found."

def audit_jwt(token):
    results = {}
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(base64url_decode(header_b64))
        payload = json.loads(base64url_decode(payload_b64))
        signature = base64url_decode(signature_b64).hex() if signature_b64 else "⚠️ No signature!"

        results["header"] = header
        results["payload"] = payload
        results["signature"] = signature

        issues, recommendations = [], []
        alg = header.get("alg", "")

        if alg.lower() == "none":
            issues.append("Token uses alg=none (no signature).")
            recommendations.append("Never accept tokens signed with 'none'.")
        if alg.upper() not in ALLOWED_ALGOS:
            issues.append(f"Suspicious algorithm: {alg}")
            recommendations.append("Use strong algorithms only (RS256, ES256, EdDSA).")

        exp = payload.get("exp")
        if not exp:
            issues.append("Missing expiration (exp).")
            recommendations.append("Always set short expiration times.")
        else:
            try:
                expiry_time = datetime.datetime.fromtimestamp(exp, datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                if expiry_time < now:
                    issues.append("Token already expired.")
                elif expiry_time - now > datetime.timedelta(hours=24):
                    issues.append("Very long expiry (over 24h).")
                    recommendations.append("Use JWT expiry under 24h.")
            except Exception:
                issues.append("Invalid exp format.")
                recommendations.append("Use UNIX timestamp for exp.")

        if payload.get("admin") is True:
            issues.append("Suspicious claim: admin privileges granted.")
            recommendations.append("Avoid sensitive claims inside JWT.")
        if payload.get("role", "").lower() in ["admin", "superuser", "root"]:
            issues.append(f"Suspicious role claim: {payload.get('role')}")
            recommendations.append("Do role checks server-side, not in JWT.")

        results["issues"] = issues
        results["recommendations"] = recommendations
        results["secret_check"] = weak_secret_key_check(token)

    except Exception as e:
        results["error"] = f"Error decoding JWT: {e}"

    return results

def generate_report(token, header, payload, issues, recommendations, filename="jwt_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=A4)
    
    # Always get fresh styles
    styles = getSampleStyleSheet()
    
    # Add custom style safely (with a new name to avoid conflicts)
    if "MyCode" not in styles:
        styles.add(ParagraphStyle(
            name="MyCode",
            fontName="Courier",
            fontSize=8,
            leading=10,
            alignment=TA_LEFT
        ))

    story = []

    # Now use the built-in Title style safely
    story.append(Paragraph("JWT Security Audit Report", styles["Title"]))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Generated on: {datetime.datetime.now()}", styles["Normal"]))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("Decoded Header:", styles["Heading2"]))
    story.append(Paragraph(json.dumps(header, indent=4), styles["MyCode"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Decoded Payload:", styles["Heading2"]))
    story.append(Paragraph(json.dumps(payload, indent=4), styles["MyCode"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Detected Vulnerabilities:", styles["Heading2"]))
    if issues:
        for v in issues:
            story.append(Paragraph(f"⚠️ {v}", styles["Normal"]))
    else:
        story.append(Paragraph("✅ No major vulnerabilities detected.", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Recommendations:", styles["Heading2"]))
    for rec in recommendations:
        story.append(Paragraph(f"👉 {rec}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("End of Report", styles["Italic"]))

    doc.build(story)
    return filename


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        token = request.form.get("jwt_token")
        results = audit_jwt(token)

        if "error" not in results:
            report_file = generate_report(
                token, results["header"], results["payload"],
                results["issues"], results["recommendations"]
            )
        else:
            report_file = None

        return render_template("result.html", token=token, results=results, report_file=report_file)

    return render_template("index.html")

@app.route("/download/<filename>")
def download(filename):
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
