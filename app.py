from flask import Flask, render_template, request
import hashlib
import hmac

app = Flask(__name__, template_folder="templates")


# ================= COMMON =================
def sha256_int(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


# ================= HOME =================
@app.route("/")
def home():
    return render_template("home.html")


# ================= ALA-1 =================
@app.route("/ala1", methods=["GET", "POST"])
def ala1():
    sign_result = None
    verify_result = None
    verify_error = None

    e = 17
    d = 413
    n = 3233

    if request.method == "POST":
        action = request.form.get("action")

        try:
            if action == "sign":
                message = request.form.get("message", "")
                hashed = sha256_int(message) % n
                signature = pow(hashed, d, n)

                sign_result = {
                    "message": message,
                    "public_key": f"(e={e}, n={n})",
                    "signature": signature,
                    "signed_hash": hashed
                }

            elif action == "verify":
                message = request.form.get("verify_message", "")
                signature = int(request.form.get("verify_signature", 0))
                public_e = int(request.form.get("verify_public_e", 0))
                public_n = int(request.form.get("verify_public_n", 0))

                expected_hash = sha256_int(message) % public_n
                recovered_hash = pow(signature, public_e, public_n)

                verify_result = {
                    "verified": expected_hash == recovered_hash,
                    "expected_hash": expected_hash,
                    "recovered_hash": recovered_hash
                }

        except Exception as err:
            verify_error = str(err)

    return render_template("ala1.html",
                           sign_result=sign_result,
                           verify_result=verify_result,
                           verify_error=verify_error)


# ================= ALA-2 =================
@app.route("/ala2", methods=["GET", "POST"])
def ala2():
    result = None
    original_text = ""
    changed_text = ""

    if request.method == "POST":
        original_text = request.form.get("text", "")
        changed_text = request.form.get("changed_text", "")

        if not changed_text:
            changed_text = original_text + "."

        def hashes(txt):
            return {
                "SHA1": hashlib.sha1(txt.encode()).hexdigest(),
                "SHA256": hashlib.sha256(txt.encode()).hexdigest(),
                "SHA512": hashlib.sha512(txt.encode()).hexdigest()
            }

        orig = hashes(original_text)
        mod = hashes(changed_text)

        def diff(a, b):
            return sum(x != y for x, y in zip(a, b))

        result = {
            "original_text": original_text,
            "changed_text": changed_text,
            "original_hashes": orig,
            "changed_hashes": mod,
            "avalanche": {
                "SHA1": {"bit_changed": diff(orig["SHA1"], mod["SHA1"]), "bit_total": 160,
                         "hex_changed": diff(orig["SHA1"], mod["SHA1"]), "hex_total": 40},
                "SHA256": {"bit_changed": diff(orig["SHA256"], mod["SHA256"]), "bit_total": 256,
                           "hex_changed": diff(orig["SHA256"], mod["SHA256"]), "hex_total": 64},
                "SHA512": {"bit_changed": diff(orig["SHA512"], mod["SHA512"]), "bit_total": 512,
                           "hex_changed": diff(orig["SHA512"], mod["SHA512"]), "hex_total": 128}
            }
        }

    return render_template("ala2.html",
                           result=result,
                           original_text=original_text,
                           changed_text=changed_text)


# ================= ALA-3 =================
@app.route("/ala3", methods=["GET", "POST"])
def ala3():
    sender_result = None
    receiver_result = None
    receiver_error = None

    sender_form = {"message": "", "key": ""}
    receiver_form = {"message": "", "key": "", "mac": ""}

    if request.method == "POST":
        action = request.form.get("action")

        try:
            if action == "send":
                msg = request.form.get("sender_message", "")
                key = request.form.get("sender_key", "")

                sender_form["message"] = msg
                sender_form["key"] = key

                mac = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()

                sender_result = {"message": msg, "mac": mac}

            elif action == "verify":
                msg = request.form.get("receiver_message", "")
                key = request.form.get("receiver_key", "")
                mac = request.form.get("receiver_mac", "")

                receiver_form["message"] = msg
                receiver_form["key"] = key
                receiver_form["mac"] = mac

                expected = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()

                valid = (mac == expected)

                receiver_result = {
                    "verified": valid,
                    "received_mac": mac,
                    "expected_mac": expected,
                    "integrity_status": "Intact" if valid else "Tampered",
                    "auth_status": "Authenticated" if valid else "Failed"
                }

        except Exception as err:
            receiver_error = str(err)

    return render_template("ala3.html",
                           sender_result=sender_result,
                           receiver_result=receiver_result,
                           receiver_error=receiver_error,
                           sender_form=sender_form,
                           receiver_form=receiver_form)


# ================= RUN =================
import os

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)