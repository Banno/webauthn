const {
    hash,
    convertASN1toPEM,
    verifySignature,
    convertCOSEPublicKeyToRawPKCSECDHAKey,
  } = require('../utils');

  exports.parseNoneKey = (authenticatorKey, clientDataJSON) => {
    const authenticatorData = parseAttestationData(authenticatorKey.authData);

    if (!authenticatorData.flags.up) {
        throw new Error('User was NOT presented during authentication!');
    }

    const publicKey = convertCOSEPublicKeyToRawPKCSECDHAKey(
        authenticatorData.COSEPublicKey
    );

    return {
        fmt: 'none',
        publicKey: publicKey.toString('base64'),
        counter: authenticatorData.counter,
        credID: authenticatorData.credID.toString('base64'),
    };
  };

  exports.validateNoneKey = (
    authenticatorDataBuffer,
    key,
    clientDataJSON,
    base64Signature
  ) => {
    const authenticatorData = parseAttestationData(authenticatorDataBuffer);

    if (!authenticatorData.flags.up) {
        throw new Error('User was NOT presented durring authentication!');
    }

    const clientDataHash = hash(
        'SHA256',
        Buffer.from(clientDataJSON, 'base64')
    );
    const signatureBase = Buffer.concat([
        authenticatorData.rpIdHash,
        authenticatorData.flagsBuf,
        authenticatorData.counterBuf,
        clientDataHash,
    ]);

    const publicKey = convertASN1toPEM(Buffer.from(key.publicKey, 'base64'));
    const signature = Buffer.from(base64Signature, 'base64');

    return verifySignature(signature, signatureBase, publicKey);
  };

  const parseAttestationData = buffer => {
    const rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    const flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    const flagsInt = flagsBuf[0];
    const flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt,
    };

    const counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    const counter = counterBuf.readUInt32BE(0);

    let aaguid;
    let credID;
    let COSEPublicKey;

    if (flags.at) {
        aaguid = buffer.slice(0, 16);
        buffer = buffer.slice(16);
        const credIDLenBuf = buffer.slice(0, 2);
        buffer = buffer.slice(2);
        const credIDLen = credIDLenBuf.readUInt16BE(0);
        credID = buffer.slice(0, credIDLen);
        buffer = buffer.slice(credIDLen);
        COSEPublicKey = buffer;
    }

    return {
        rpIdHash,
        flagsBuf,
        flags,
        counter,
        counterBuf,
        aaguid,
        credID,
        COSEPublicKey,
    };
  };
