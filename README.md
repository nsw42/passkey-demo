# Passkey demonstration

This is a _relatively_ simple demonstration  of passkeys. It glues together various information that
is spread across multiple websites, library documentation and blogs.

## Credit and references

<https://web.dev/articles/passkey-registration> and <https://web.dev/articles/passkey-form-autofill>
were particularly helpful in figuring out what was needed for the front-end, and
<https://pypi.org/project/webauthn/> helped me figure out the backend.

The file `base64url-arraybuffer.js` is from <https://github.com/herrjemand/Base64URL-ArrayBuffer>.

## Notes

The Python code generates a self-signed certificate on first run, because passkeys are only
supported over https links.

`db.py` is a relatively simple interface to a user database, without any effort to optimise (e.g. by
adding indexes).

## Possible improvements

The use of client IP address to maintain the (in-memory) database of login attempts/challenges is
fragile: multiple people trying to log in at the same time could collide, and someone on a mobile
could see their address change between loading the page and actually logging in. However, this is
the best option I can see: we don't have any information about the user when we're calling
`/api/generate-authentication-options` from the UI, so can't tie the challenge to that account.

The other option is to make the user type in their username, even though it's implied by the passkey.
This seems like a backwards step for UX.

<https://github.com/w3c/webauthn/issues/1856> and <https://github.com/w3c/webauthn/issues/1848>
both talk about different aspects of the complexity of server-side management of challenges. Not
all of the advice from those discussions is included in this demo. (E.g. there's a suggestion that
the client should generate new challenges if the login timeout nears)
