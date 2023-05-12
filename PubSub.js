// Built-in
const HTTP = require('http');
const URL = require('url');
const FS = require("fs");

// Installed
const WebSocketServer = require('websocket').server;

// Written
import AES from './AES.js';
import JSOBS from './jsobs/jsobs.js';
import configuration from "./configuration.js";

String.prototype.b16ToAB = function() {
	let str = (0 == (this.length % 2)) ? this : ("0" + this);
	let buffer = new Buffer(str.length / 2);
	for (let j = 0; j < buffer.length; j++) {
		let s = str.substring(2 * j, 2 * j + 2);
		buffer[j] = parseInt(s, 16);
	}
	return buffer;
};

String.prototype.b64ToAB = function(url = false) {
	let base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' + (url ? '-_' : '+/');
	let str = this.replace(/=/gi, "");
	let length = Math.floor(str.length * 6 / 8);
	let buffer = new Buffer(length);
	for (let i = 0, si = -1; i < length; i++) {
		let m = 2 * (i % 3), e1 = 6 - m, b1 = 2**e1 - 1;
		si += +(0 == i % 3);
		let c = str[si], ci1 = base64Chars.indexOf(c);
		buffer[i] = (ci1 & b1) << (2 + m);
		let e2 = 4 - m, b2 = 63 - (2**e2 - 1), c2 = str[++si] || 'A', ci2 = base64Chars.indexOf(c2);
		buffer[i] |= (ci2 & b2) >> (4 - m);
	}
	return buffer;
};

let PubSub = function() {
	this.topics = {};
	this.aes = new AES.GCM(configuration.key);

	this.http = HTTP.createServer(function(request, response) {
		response.writeHead(404);
		response.end();
	});
	
	this.http.listen(configuration.port, function () {
		console.log('Room Server is listening on port 5454');
	});
	
	this.ws = new WebSocketServer({
		httpServer : this.http,
		autoAcceptConnections : false
	});
	this.ws.on('request', this.onrequest.bind(this));
};

PubSub.prototype.onrequest = async function(request) {
	try {
		let filename = request.resourceURL.pathname.replace(/\//g, '');
		let fileAddress = `data/${filename}`;
		let fileExists = FS.existsSync(fileAddress);
		if (fileExists) {
			let buffer = FS.readFileSync(fileAddress);
			let content = this.aes.decrypt(buffer);
			let uint8Array = new Uint8Array(content);
			let user = JSOBS.deserialize(uint8Array.buffer);
			let userAES = new AES.GCM(user.key);
			let params = URL.parse(request.resourceURL.href, true);
			let encryptedLoginBuffer = params.query.login.b64ToAB(true);
			let decryptedLoginBuffer = userAES.decrypt(encryptedLoginBuffer);
			let decryptedLoginArray = new Uint8Array(decryptedLoginBuffer);
			let login = JSOBS.deserialize(decryptedLoginArray.buffer);
			if ((user.last|0) < login.date) {	
				user.last = login.date;
				let userArrayBuffer = JSOBS.serialize(user);
				let userBuffer = new Buffer(userArrayBuffer);
				let encryptedUserBuffer = this.aes.encrypt(userBuffer);
				FS.writeFileSync(fileAddress, encryptedUserBuffer);
				var connection = request.accept('data', request.origin);
				connection.aes = userAES;
				connection.on('message', this.onmessage.bind(this, connection));
				connection.on('close', this.onclose.bind(this, connection));
			} else {
				request.reject();
			}
		} else {
			request.reject();
		}
	} catch (e) {
		request.reject();
		console.log("Service.onrequest: ");
		console.log(e);
	}
};

PubSub.prototype.onmessage = function(connection, e) {
	let messageBuffer = connection.aes.decrypt(e.binaryData);
	let uint8Array = new Uint8Array(messageBuffer);
	let message = JSOBS.deserialize(uint8Array.buffer);
	switch(message.name) {
		case 'pub':
			this.publish(connection, message);
			break;
		case 'sub':
			this.subscribe(connection, message);
			break;
		case 'uns':
			this.unsubscribe(connection, message);
			break;
	}
};

PubSub.prototype.onclose = function(connection) {
	let topics = connection.topics || [];
	for (let topic of topics) {
		if (topic in this.topics) {
			let connections = this.topics[topic];
			let cindex = connections.indexOf(connection);
			if (0 <= cindex) {
				connections.splice(cindex, 1);
				if (0 >= connections.length) {
					delete this.topics[topic];
				}
			}
		}
	}
};

PubSub.prototype.subscribe = function(connection, message) {
	let topic = this.topics[message.topic] = this.topics[message.topic] || [];
	let index = topic.indexOf(connection);
	if (0 > index) {
		topic.push(connection);
		connection.topics = connection.topics = connection.topics || [];
		let tindex = connection.topics.indexOf(message.topic);
		if (0 > tindex) {
			connection.topics.push(message.topic);
		}
	}
};

PubSub.prototype.unsubscribe = function(connection, message) {
	// TODO:: 
};

PubSub.prototype.publish = function(connection, message) {
	let messageArrayBuffer = JSOBS.serialize(message);
	let messageBuffer = new Buffer(messageArrayBuffer);
	let topic = this.topics[message.topic] = this.topics[message.topic] || [];
	for (let saved of topic) {
		if (saved != connection) {
			let encryptedBuffer = saved.aes.encrypt(messageBuffer);
			saved.send(encryptedBuffer);
		}
	}
};


PubSub.instance = new PubSub();
process.on('uncaughtException', function(error) {
	console.log("ERROR:");
	console.log(error);
});


