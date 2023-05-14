// Built-in
import HTTP from 'http';
import URL from 'url';
import FS from "fs";

// Installed
import WebSocket from 'websocket';

// Written
import AES from './aes/AES.js';
import JSOBS from './jsobs/jsobs.js';
import Convert from './convert/Convert.js';
import configuration from "./configuration.js";


let PubSub = function() {
	this.topics = {};
	var keyBuffer = Convert.B16.toAB(configuration.key);
	this.aes = new AES.GCM(keyBuffer);

	this.http = HTTP.createServer(function(request, response) {
		response.writeHead(404);
		response.end();
	});
	
	this.http.listen(configuration.port, function () {
		console.log('Room Server is listening on port 5454');
	});
	
	this.ws = new WebSocket.server({
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
			// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			let fileBuffer = FS.readFileSync(fileAddress);
			var fileArrayBuffer = fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength);
			// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			
			let serializedUser = await this.aes.decrypt(fileArrayBuffer);
			let user = JSOBS.deserialize(serializedUser);
			let userAES =  new AES.GCM(user.key);
			let params = URL.parse(request.resourceURL.href, true);
			let encryptedLoginArrayBuffer = Convert.B64.toAB(params.query.login, true);
			let decryptedLoginArrayBuffer = await userAES.decrypt(encryptedLoginArrayBuffer);
			let login = JSOBS.deserialize(decryptedLoginArrayBuffer);
			if ((user.last|0) < login.date) {	
				user.last = login.date;
				let userArrayBuffer = JSOBS.serialize(user);
				let encryptedUserArrayBuffer = await this.aes.encrypt(userArrayBuffer);
				
				// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
				let encryptedUserBuffer = Buffer.from(encryptedUserArrayBuffer);
				FS.writeFileSync(fileAddress, encryptedUserBuffer);
				// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
				
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
		console.log(e.stack);
	}
};

PubSub.prototype.onmessage = async function(connection, e) {
	// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	var arrayBuffer = e.binaryData.buffer.slice(e.binaryData.byteOffset, e.binaryData.byteOffset + e.binaryData.byteLength);
	// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	let messageBuffer = await connection.aes.decrypt(arrayBuffer);
	let message = JSOBS.deserialize(messageBuffer);
	switch(message.name) {
		case 'pub':
			await this.publish(connection, message);
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

PubSub.prototype.publish = async function(connection, message) {
	let messageArrayBuffer = JSOBS.serialize(message);
	let messageBuffer = Buffer.from(messageArrayBuffer);
	let topic = this.topics[message.topic] = this.topics[message.topic] || [];
	for (let saved of topic) {
		if (saved != connection) {
			let encryptedArrayBuffer = await saved.aes.encrypt(messageBuffer);
			let encryptedBuffer = Buffer.from(encryptedArrayBuffer);
			saved.send(encryptedBuffer);
		}
	}
};


PubSub.instance = new PubSub();
process.on('uncaughtException', function(error) {
	console.log("ERROR:");
	console.log(error);
});


