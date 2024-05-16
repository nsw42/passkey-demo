from dataclasses import dataclass
from datetime import datetime, timedelta
import http
import os.path
import subprocess

from flask import Flask, abort, request
import webauthn
from webauthn.helpers.exceptions import InvalidJSONStructure, InvalidRegistrationResponse

from db import Database, User


@dataclass
class LoginAttempt:
    start_time: datetime
    challenge: str


app = Flask(__name__)
app.db = Database(app)
app.login_challenges = {}  # dict[str, LoginAttempt] - map username to login attempt information

RP_ID = 'localhost'  # 'yourdomain.com'
RP_NAME = 'My co'

CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'


@app.route('/')
def root():
    with open('index.html', encoding='utf-8') as handle:
        return handle.read()


@app.route('/base64url-arraybuffer.js')
def base64url_arraybuffer():
    with open('base64url-arraybuffer.js', encoding='utf-8') as handle:
        return handle.read()


@app.route('/root.js')
def root_js():
    with open('root.js', encoding='utf-8') as handle:
        return handle.read()


@app.post('/api/generate-authentication-options')
def generate_authentication_options():
    opts = webauthn.generate_authentication_options(rp_id=RP_ID)
    # Using remote_addr isn't ideal, but we don't have username or passkeyid yet
    app.login_challenges[request.remote_addr] = LoginAttempt(datetime.now(), opts.challenge)
    return webauthn.options_to_json(opts)


@app.post('/api/login-with-passkey')
def login_with_passkey():
    body = request.json
    passkeyid = body.get('id')
    user = app.db.get_user_by_passkeyid(passkeyid) if passkeyid else None
    if not user:
        abort(http.HTTPStatus.UNAUTHORIZED, 'User id does not exist')
    login_attempt = app.login_challenges.get(request.remote_addr)
    if not login_attempt:
        abort(http.HTTPStatus.UNAUTHORIZED, 'No login attempt')
    if datetime.now() - login_attempt.start_time > timedelta(minutes=3):
        abort(http.HTTPStatus.REQUEST_TIMEOUT, 'Login attempt expired')
    try:
        response = webauthn.verify_authentication_response(
            credential=body,
            expected_challenge=login_attempt.challenge,
            expected_rp_id=RP_ID,
            expected_origin='https://' + RP_ID,
            credential_public_key=user.publickey,
            credential_current_sign_count=user.signcount
        )
    except webauthn.helpers.exceptions.InvalidAuthenticationResponse as e:
        abort(http.HTTPStatus.UNAUTHORIZED, str(e))
    app.db.save_user_signcount(passkeyid, response.new_sign_count)
    return ('', http.HTTPStatus.NO_CONTENT)


@app.post('/api/generate-registration-options')
def generate_registration_options():
    username = request.form['username']
    displayname = request.form['displayname']
    opts = webauthn.generate_registration_options(rp_id=RP_ID,
                                                  rp_name=RP_NAME,
                                                  user_name=username,
                                                  user_display_name=displayname)
    if not app.db.add_user(User(username, None, displayname, opts.challenge, None, 0)):
        user = app.db.get_user_by_username(username)
        if user.publickey:
            abort(http.HTTPStatus.CONFLICT, 'Username already exists')
        else:
            # The user had only got part-way through registration
            # This seems like a possible race: two users trying to register at the same time,
            # with the same username; however, only one of them will succeed
            # in the verify_registration_response stage, because of the
            # different challenges.
            # There's scope to improve the error reporting for this scenario,
            # but it's sufficiently unlikely that I haven't bothered.
            app.db.save_user_challenge(username, opts.challenge)
    return webauthn.options_to_json(opts)


@app.post('/api/register-with-passkey')
def register_with_passkey():
    body = request.json
    username = body.get('username')
    user = app.db.get_user_by_username(username) if username else None
    if not user:
        abort(http.HTTPStatus.UNAUTHORIZED, 'Username does not exist')
    credential = body.get('credential')
    if not credential:
        abort(http.HTTPStatus.BAD_REQUEST, 'No credential provided')
    try:
        response = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=user.challenge,
            expected_rp_id=RP_ID,
            expected_origin='https://' + RP_ID
        )
    except (InvalidJSONStructure, InvalidRegistrationResponse) as e:
        abort(http.HTTPStatus.BAD_REQUEST, str(e))
    if not response.user_verified:
        abort(http.HTTPStatus.UNAUTHORIZED, 'Registration verification failed')
    app.db.save_user_passkey(username, credential['id'], response.credential_public_key)
    return ('', http.HTTPStatus.NO_CONTENT)


def generate_selfsigned_cert():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        subprocess.run(['openssl', 'req',
                        '-x509',
                        '-nodes',
                        '-days', '365',
                        '-newkey', 'rsa:4096',
                        '-keyout', KEY_FILE,
                        '-out', CERT_FILE,
                        '-subj', f'/CN={RP_ID}/O={RP_NAME}'],
                       check=True)


if __name__ == '__main__':
    generate_selfsigned_cert()
    app.run(host='0.0.0.0', port=443, debug=True, ssl_context=(CERT_FILE, KEY_FILE))
