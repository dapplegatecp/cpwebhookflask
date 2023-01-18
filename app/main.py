import hmac
import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger('werkzeug')

SECRET = "super secret key"
X_SIG = "x-cp-signature"

@app.post("/")
def webhook():
    msg_body = request.get_data()
    logger.info("Body: %s", msg_body)
    logger.info("Headers: %s", request.headers)

    xsig = request.headers.get(X_SIG)
    sig = hmac.new(key=SECRET.encode('utf-8'), msg=msg_body, digestmod="sha256").hexdigest()

    logger.info("xsig: %s", xsig)
    logger.info("sig: %s", sig)

    if xsig == sig:
        return "", 200
    
    return "", 403

if __name__ == "__main__":
    app.run(debug=True, port=8443, host='0.0.0.0', ssl_context=('cert/cert.pem', 'cert/key.pem'))