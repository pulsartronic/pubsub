import crypto from 'crypto';

let AES = {};

AES.GCM = function(key) {
	this.key = key.b16ToAB();
};

AES.GCM.prototype.encrypt = function(dataBuffer) {
	var iv = new Buffer(crypto.randomBytes(12));
	var cipher = crypto.createCipheriv("aes-256-gcm", this.key, iv);
	var encryptedBuffer = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
	var authTag = cipher.getAuthTag();
	let buffer = Buffer.concat([iv, encryptedBuffer, authTag]);
	return buffer;
};

AES.GCM.prototype.decrypt = function(dataBuffer) {
	var iv = dataBuffer.slice(0, 12);
	var encryptedBuffer = dataBuffer.slice(12, dataBuffer.length - 16);
	var authTag = dataBuffer.slice(dataBuffer.length - 16, dataBuffer.length);
	var decipher = crypto.createDecipheriv("aes-256-gcm", this.key, iv);
	decipher.setAuthTag(authTag);
	let buffer = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
	return buffer;
};

export default AES;
