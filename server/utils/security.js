// server/utils/security.js
const crypto = require('crypto');
const { clientEncryption } = require('../models/User');

const algorithm = 'aes-256-ctr';
const secretKey = process.env.ENCRYPTION_SECRET_KEY;
const iv = crypto.randomBytes(16);

// To Encrypt Text
const encrypt = (text) =>{
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// To Decrypt Text
const decrypt = (hash) => {
    const parts = hash.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString();
};

module.exports = {encrypt, decrypt};