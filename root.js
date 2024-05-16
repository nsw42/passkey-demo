$(() => {
    'use strict'

    const loginAbortController = new AbortController()

    if (window.PublicKeyCredential &&
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        PublicKeyCredential.isConditionalMediationAvailable)
    {
        Promise.all([
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            PublicKeyCredential.isConditionalMediationAvailable(),
        ]).then(results => {
            if (results.every(r => r === true)) {
                // Passkey supported on this browser, so:
                // (a) default to registering with a passkey
                $('#register-use-passkey').prop('disabled', false).prop('checked', true)

                // (b) Prepare login for logging in with any existing passkey
                prepareLoginWithPasskey()
            }
        })
    }

    // Interactive behaviour
    $('input[type=radio][name=register-use-passkey]').on('change', function() {
        if (this.value === 'passkey') {
            $('#register-with-passkey-container').removeClass('d-none')
            $('#register-with-password-container').addClass('d-none')
        } else {
            $('#register-with-passkey-container').addClass('d-none')
            $('#register-with-password-container').removeClass('d-none')
        }
    })

    // Registration validation and submission
    const $registerForm = $('#register-form')
    const registerForm = $registerForm[0]
    $registerForm.on('submit', (event) => {
        $registerForm.addClass('was-validated')
        $('#register-username').removeClass('is-invalid')

        event.preventDefault()
        event.stopPropagation()

        if (!registerForm.checkValidity()) {
            return
        }

        if (event.originalEvent.submitter.id === 'register-with-passkey') {
            loginAbortController.abort("Starting registration")
            registerWithPasskey()
        } else {
            alert('Passwords not supported in this demo')
        }
    })

    function registerWithPasskey() {
        $.ajax({
            url: '/api/generate-registration-options',
            method: 'POST',
            data: {
                username: $('#register-username').val(),
                displayname: $('#register-displayname').val(),
            },
            dataType: 'json',
            success: completeRegisterWithPasskey,
            error: (_xhr, _status, error) => {
                if (error === 'CONFLICT') {
                    $registerForm.removeClass('was-validated')
                    $('#register-username').addClass('is-invalid')
                    $('#register-username-feedback').text('Username already taken')
                }
            }
        })
    }

    async function completeRegisterWithPasskey(options) {
        options['challenge'] = window.base64url.decode(options['challenge'])
        options['user']['id'] = window.base64url.decode(options['user']['id'])
        const credential = await navigator.credentials.create({publicKey: options})
        $.ajax({
            url: '/api/register-with-passkey',
            method: 'POST',
            data: JSON.stringify({
                username: $('#register-username').val(),
                credential: {
                    authenticatorAttachment: credential.authenticatorAttachment,
                    id: credential.id,
                    rawId: window.base64url.encode(credential.rawId),
                    response: {
                        attestationObject: window.base64url.encode(credential.response.attestationObject),
                        clientDataJSON: window.base64url.encode(credential.response.clientDataJSON),
                    },
                    type: credential.type,
                }
            }),
            contentType: 'application/json',
            success: () => {
                $('#register-with-passkey').addClass('d-none')
                $('#registration-result').text('Registration successful')
            },
            error: (_xhr, _status, error) => {
                $('#registration-result').text('Registration failed:', error)
            }
        })
    }

    // Login validation and submission
    const $loginForm = $('#login-form')
    const loginForm = $loginForm[0]
    $loginForm.on('submit', (event) => {
        $loginForm.addClass('was-validated')

        if (!loginForm.checkValidity()) {
            event.preventDefault()
            event.stopPropagation()
            return
        }

        alert('Passwords not supported in this demo')
    })

    function prepareLoginWithPasskey() {
        $.ajax({
            url: '/api/generate-authentication-options',
            method: 'POST',
            data: {
                username: $('#login-username').val(),
            },
            dataType: 'json',
            success: (options) => {
                options['challenge'] = window.base64url.decode(options['challenge'])
                navigator.credentials.get({
                    publicKey: options,
                    signal: loginAbortController.signal,
                    mediation: 'conditional'
                }).then(credential => completeLoginWithPasskey(credential),
                        () => {})  // Login (probably) aborted because of starting registration
            },
            error: (_xhr, _status, error) => {
                console.log('login error', error)
                if (error === 'UNAUTHORIZED') {
                    $loginForm.removeClass('was-validated')
                    $('#login-username').addClass('is-invalid')
                    $('#login-username-feedback').text('Unknown username')
                } else {
                    $('#login-result').text('Login failed:' + error)
                }
            }
        })
    }

    async function completeLoginWithPasskey(credential) {
        console.log('credential', credential)
        $.ajax({
            url: '/api/login-with-passkey',
            method: 'POST',
            data: JSON.stringify({
                id: credential.id,
                rawId: window.base64url.encode(credential.rawId),
                response: {
                    authenticatorData: window.base64url.encode(credential.response.authenticatorData),
                    clientDataJSON: window.base64url.encode(credential.response.clientDataJSON),
                    signature: window.base64url.encode(credential.response.signature),
                },
                type: credential.type,
            }),
            contentType: 'application/json',
            success: () => {
                $('#login-form').addClass('d-none')
                $('#login-result').text('Logged in!')
            },
            error: (_xhr, _status, error) => {
                switch (error) {
                case 'UNAUTHORIZED':
                    $loginForm.removeClass('was-validated')
                    $('#login-username').removeClass('is-invalid')
                    $('#login-result').text('Login failed:', error)
                    break
                case 'REQUEST TIMEOUT':
                    $('#login-result').text('Login timed out. Please try again.')
                    prepareLoginWithPasskey()
                    break
                default:
                    $('#login-result').text('Login failed:' + error)
                    break
                }
            }
        })
    }
})
