const { decodeAllSync } = require('cbor');
const { parseAndroidSafetyNetKey } = require('./parseAndroidSafetyNetKey');
const { parseFidoU2FKey } = require('./parseFidoU2FKey');
const { parseFidoPackedKey } = require('./parseFidoPackedKey');
const { parseNoneKey } = require('./parseNoneKey');

exports.getAuthenticatorKeyId = key_id => {
    const buffer = Buffer.from(key_id, 'base64');
    return buffer.toString('base64');
};

exports.parseAuthenticatorKey = async (credentials) => {
    const authenticatorKeyBuffer = Buffer.from(credentials.attestationObject, 'base64');

    const authenticatorKey = decodeAllSync(authenticatorKeyBuffer)[0];

    if (authenticatorKey.fmt === 'android-safetynet') {
        return parseAndroidSafetyNetKey(authenticatorKey, credentials.clientDataJSON);
    }

    if (authenticatorKey.fmt === 'fido-u2f') {
        return parseFidoU2FKey(authenticatorKey, credentials.clientDataJSON);
    }

    if (authenticatorKey.fmt === 'none') {
        return parseNoneKey(authenticatorKey, credentials.clientDataJSON);
    }

    if (authenticatorKey.fmt === 'packed') {
        return parseFidoPackedKey(authenticatorKey, credentials.clientDataJSON);
    }

    return undefined;
};
