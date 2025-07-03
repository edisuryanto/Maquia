// _worker.src.js
import { connect } from "cloudflare:sockets";

let password = '';
let proxyIP = '';
// The user name and password do not contain special characters
// Setting the address will ignore proxyIP
// Example:  user:pass@host:port  or  host:port
let socks5Address = '';

let addresses = [
	//å½“subä¸ºç©ºæ—¶å¯ç”¨æœ¬åœ°ä¼˜é€‰åŸŸå/ä¼˜é€‰IPï¼Œè‹¥ä¸å¸¦ç«¯å£å· TLSé»˜è®¤ç«¯å£ä¸º443ï¼Œ#å·åŽä¸ºå¤‡æ³¨åˆ«å
];

let sub = ''; 
let subconverter = 'SUBAPI.fxxk.dedyn.io';// clashè®¢é˜…è½¬æ¢åŽç«¯ï¼Œç›®å‰ä½¿ç”¨CMçš„è®¢é˜…è½¬æ¢åŠŸèƒ½ã€‚è‡ªå¸¦è™šå‡èŠ‚ç‚¹ä¿¡æ¯é˜²æ³„éœ²
let subconfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini"; //è®¢é˜…é…ç½®æ–‡ä»¶
let subProtocol = 'https';
let RproxyIP = 'false';

let addressesapi = [];
let addressescsv = [];
let DLS = 8;

let FileName = 'epeius';
let BotToken ='';
let ChatID =''; 
let proxyhosts = [];//æœ¬åœ°ä»£ç†åŸŸåæ± 
let proxyhostsURL = '';
let go2Socks5s = [
	'*ttvnw.net',
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*.loadshare.org',
];

let fakeUserID ;
let fakeHostName ;
let proxyIPs ;
let socks5s;
let sha224Password ;
const expire = 4102329600;//2099-12-31
const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;

let parsedSocks5Address = {}; 
let enableSocks = false;
let httpsPorts = ["2053","2083","2087","2096","8443"];
/*Obfuscate-cmliu*/
/*
if (!isValidSHA224(sha224Password)) {
	throw new Error('sha224Password is not valid');
}
*/
export default {
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			password = env.PASSWORD || password;
			if (!password) {
				return new Response('è¯·è®¾ç½®ä½ çš„PASSWORDå˜é‡ï¼Œæˆ–å°è¯•é‡è¯•éƒ¨ç½²ï¼Œæ£€æŸ¥å˜é‡æ˜¯å¦ç”Ÿæ•ˆï¼Ÿ', { 
					status: 404,
					headers: {
						"Content-Type": "text/plain;charset=utf-8",
					}
				});
			}
			sha224Password = env.SHA224 || env.SHA224PASS || sha224(password);
			//console.log(sha224Password);

			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0); // è®¾ç½®æ—¶é—´ä¸ºå½“å¤©
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDMD5 = await MD5MD5(`${password}${timestamp}`);
			fakeUserID = fakeUserIDMD5.slice(0, 8) + "-" + fakeUserIDMD5.slice(8, 12) + "-" + fakeUserIDMD5.slice(12, 16) + "-" + fakeUserIDMD5.slice(16, 20) + "-" + fakeUserIDMD5.slice(20);
			fakeHostName = fakeUserIDMD5.slice(6, 9) + "." + fakeUserIDMD5.slice(13, 19);
			//console.log(fakeUserID); // æ‰“å°fakeID
			
			proxyIP = env.PROXYIP || proxyIP;
			proxyIPs = await ADD(proxyIP);
			proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			socks5Address = env.SOCKS5 || socks5Address;
			socks5s = await ADD(socks5Address);
			socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
			socks5Address = socks5Address.split('//')[1] || socks5Address;
			if (env.CFPORTS) httpsPorts = await ADD(env.CFPORTS);
			sub = env.SUB || sub;
			subconverter = env.SUBAPI || subconverter;
			if( subconverter.includes("http://") ){
				subconverter = subconverter.split("//")[1];
				subProtocol = 'http';
			} else {
				subconverter = subconverter.split("//")[1] || subconverter;
			}
			subconfig = env.SUBCONFIG || subconfig;
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					RproxyIP = env.RPROXYIP || 'false';
					enableSocks = true;
				} catch (err) {
  					/** @type {Error} */ 
					let e = err;
					console.log(e.toString());
					RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
					enableSocks = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
			}
			if (env.ADD) addresses = await ADD(env.ADD);
			if (env.ADDAPI) addressesapi = await ADD(env.ADDAPI);
			if (env.ADDCSV) addressescsv = await ADD(env.ADDCSV);
			DLS = env.DLS || DLS;
			BotToken = env.TGTOKEN || BotToken;
			ChatID = env.TGID || ChatID; 
			if(env.GO2SOCKS5) go2Socks5s = await ADD(env.GO2SOCKS5);
			const upgradeHeader = request.headers.get("Upgrade");
			const url = new URL(request.url);
			if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');
			FileName = env.SUBNAME || FileName;
			if (!upgradeHeader || upgradeHeader !== "websocket") {
				//const url = new URL(request.url);
				switch (url.pathname) {
				case '/':
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: {
							'content-type': 'application/json',
						},
					});
				case `/${fakeUserID}`:
					const fakeConfig = await getTrojanConfig(password, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url);
					return new Response(`${fakeConfig}`, { status: 200 });
				case `/${password}`:
					await sendMessage(`#èŽ·å–è®¢é˜… ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\nåŸŸå: ${url.hostname}\n<tg-spoiler>å…¥å£: ${url.pathname + url.search}</tg-spoiler>`);
					const trojanConfig = await getTrojanConfig(password, request.headers.get('Host'), sub, UA, RproxyIP, url);
					const now = Date.now();
					//const timestamp = Math.floor(now / 1000);
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776 ;

					if (userAgent && (userAgent.includes('mozilla') || userAgent.includes('subconverter'))){
						return new Response(`${trojanConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					} else {
						return new Response(`${trojanConfig}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				default:
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response('ä¸ç”¨æ€€ç–‘ï¼ä½ PASSWORDå°±æ˜¯é”™çš„ï¼ï¼ï¼', { status: 404 });
				}
			} else {
				proxyIP = url.searchParams.get('proxyip') || proxyIP;
				if (new RegExp('/proxyip=', 'i').test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
				else if (new RegExp('/proxyip.', 'i').test(url.pathname)) proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;

				socks5Address = url.searchParams.get('socks5') || socks5Address;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')){
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
						socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
					}
				}
				if (socks5Address) {
					try {
						parsedSocks5Address = socks5AddressParser(socks5Address);
						enableSocks = true;
					} catch (err) {
						/** @type {Error} */ 
						let e = err;
						console.log(e.toString());
						enableSocks = false;
					}
				} else {
					enableSocks = false;
				}
				return await trojanOverWSHandler(request);
			}
		} catch (err) {
			let e = err;
			return new Response(e.toString());
		}
	}
};

async function trojanOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();
	let address = "";
	let portWithRandomLog = "";
	const log = (info, event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
	};
	const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
	let remoteSocketWapper = {
		value: null
	};
	let udpStreamWrite = null;
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}
			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = "",
				rawClientData,
				addressType
			} = await parseTrojanHeader(chunk);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
			if (hasError) {
				throw new Error(message);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log, addressType);
		},
		close() {
			log(`readableWebSocketStream is closed`);
		},
		abort(reason) {
			log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
		}
	})).catch((err) => {
		log("readableWebSocketStream pipeTo error", err);
	});
	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client
	});
}

async function parseTrojanHeader(buffer) {
	if (buffer.byteLength < 56) {
		return {
			hasError: true,
			message: "invalid data"
		};
	}
	let crLfIndex = 56;
	if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
		return {
			hasError: true,
			message: "invalid header format (missing CR LF)"
		};
	}
	const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
	if (password !== sha224Password) {
		return {
			hasError: true,
			message: "invalid password"
		};
	}

	const socks5DataBuffer = buffer.slice(crLfIndex + 2);
	if (socks5DataBuffer.byteLength < 6) {
		return {
			hasError: true,
			message: "invalid SOCKS5 request data"
		};
	}

	const view = new DataView(socks5DataBuffer);
	const cmd = view.getUint8(0);
	if (cmd !== 1) {
		return {
			hasError: true,
			message: "unsupported command, only TCP (CONNECT) is allowed"
		};
	}

	const atype = view.getUint8(1);
	// 0x01: IPv4 address
	// 0x03: Domain name
	// 0x04: IPv6 address
	let addressLength = 0;
	let addressIndex = 2;
	let address = "";
	switch (atype) {
	case 1:
		addressLength = 4;
		address = new Uint8Array(
			socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
		).join(".");
		break;
	case 3:
		addressLength = new Uint8Array(
			socks5DataBuffer.slice(addressIndex, addressIndex + 1)
		)[0];
		addressIndex += 1;
		address = new TextDecoder().decode(
			socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
		);
		break;
	case 4:
		addressLength = 16;
		const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
		const ipv6 = [];
		for (let i = 0; i < 8; i++) {
			ipv6.push(dataView.getUint16(i * 2).toString(16));
		}
		address = ipv6.join(":");
		break;
	default:
		return {
			hasError: true,
			message: `invalid addressType is ${atype}`
		};
	}

	if (!address) {
		return {
			hasError: true,
			message: `address is empty, addressType is ${atype}`
		};
	}

	const portIndex = addressIndex + addressLength;
	const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);
	return {
		hasError: false,
		addressRemote: address,
		portRemote,
		rawClientData: socks5DataBuffer.slice(portIndex + 4),
		addressType: atype
	};
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log, addressType) {
	async function useSocks5Pattern(address) {
		if ( go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg==')) ) return true;
		return go2Socks5s.some(pattern => {
			let regexPattern = pattern.replace(/\*/g, '.*');
			let regex = new RegExp(`^${regexPattern}$`, 'i');
			return regex.test(address);
		});
	}
	async function connectAndWrite(address, port, socks = false) {
		log(`connected to ${address}:${port}`);
		//if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
		: connect({
			hostname: address,
			port
		});
		remoteSocket.value = tcpSocket;
		//log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}
	async function retry() {
		if (enableSocks) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			if (!proxyIP || proxyIP == '') {
				proxyIP = atob('UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==');
			} else if (proxyIP.includes(']:')) {
				portRemote = proxyIP.split(']:')[1] || portRemote;
				proxyIP = proxyIP.split(']:')[0] || proxyIP;
			} else if (proxyIP.split(':').length === 2) {
				portRemote = proxyIP.split(':')[1] || portRemote;
				proxyIP = proxyIP.split(':')[0] || proxyIP;
			}
			if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		}
		tcpSocket.closed.catch((error) => {
			console.log("retry tcpSocket closed error", error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		});
		remoteSocketToWS(tcpSocket, webSocket, null, log);
	}
	let useSocks = false;
	if( go2Socks5s.length > 0 && enableSocks ) useSocks = await useSocks5Pattern(addressRemote);
	let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);
	remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener("message", (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});
			webSocketServer.addEventListener("close", () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});
			webSocketServer.addEventListener("error", (err) => {
				log("webSocketServer error");
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},
		pull(controller) {},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`readableStream was canceled, due to ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});
	return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
	let hasIncomingData = false;
	await remoteSocket.readable.pipeTo(
		new WritableStream({
			start() {},
			/**
			 *
			 * @param {Uint8Array} chunk
			 * @param {*} controller
			 */
			async write(chunk, controller) {
				hasIncomingData = true;
				if (webSocket.readyState !== WS_READY_STATE_OPEN) {
					controller.error(
						"webSocket connection is not open"
					);
				}
				webSocket.send(chunk);
			},
			close() {
				log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
			},
			abort(reason) {
				console.error("remoteSocket.readable abort", reason);
			}
		})
	).catch((error) => {
		console.error(
			`remoteSocketToWS error:`,
			error.stack || error
		);
		safeCloseWebSocket(webSocket);
	});
	if (hasIncomingData === false && retry) {
		log(`retry`);
		retry();
	}
}
/*
function isValidSHA224(hash) {
	const sha224Regex = /^[0-9a-f]{56}$/i;
	return sha224Regex.test(hash);
}
*/
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error("safeCloseWebSocket error", error);
	}
}

/*
export {
	worker_default as
	default
};
//# sourceMappingURL=worker.js.map
*/

function revertFakeInfo(content, userID, hostName, isBase64) {
	if (isBase64) content = atob(content);//Base64è§£ç 
	content = content.replace(new RegExp(fakeUserID, 'g'), userID).replace(new RegExp(fakeHostName, 'g'), hostName);
	//console.log(content);
	if (isBase64) content = btoa(content);//Base64ç¼–ç 

	return content;
}

async function MD5MD5(text) {
	const encoder = new TextEncoder();
  
	const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstPassArray = Array.from(new Uint8Array(firstPass));
	const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondPassArray = Array.from(new Uint8Array(secondPass));
	const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
	return secondHex.toLowerCase();
}

async function ADD(å†…å®¹) {
	// å°†åˆ¶è¡¨ç¬¦ã€åŒå¼•å·ã€å•å¼•å·å’Œæ¢è¡Œç¬¦éƒ½æ›¿æ¢ä¸ºé€—å·
	// ç„¶åŽå°†è¿žç»­çš„å¤šä¸ªé€—å·æ›¿æ¢ä¸ºå•ä¸ªé€—å·
	var æ›¿æ¢åŽçš„å†…å®¹ = å†…å®¹.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
	
	// åˆ é™¤å¼€å¤´å’Œç»“å°¾çš„é€—å·ï¼ˆå¦‚æžœæœ‰çš„è¯ï¼‰
	if (æ›¿æ¢åŽçš„å†…å®¹.charAt(0) == ',') æ›¿æ¢åŽçš„å†…å®¹ = æ›¿æ¢åŽçš„å†…å®¹.slice(1);
	if (æ›¿æ¢åŽçš„å†…å®¹.charAt(æ›¿æ¢åŽçš„å†…å®¹.length - 1) == ',') æ›¿æ¢åŽçš„å†…å®¹ = æ›¿æ¢åŽçš„å†…å®¹.slice(0, æ›¿æ¢åŽçš„å†…å®¹.length - 1);
	
	// ä½¿ç”¨é€—å·åˆ†å‰²å­—ç¬¦ä¸²ï¼Œå¾—åˆ°åœ°å€æ•°ç»„
	const åœ°å€æ•°ç»„ = æ›¿æ¢åŽçš„å†…å®¹.split(',');
	
	return åœ°å€æ•°ç»„;
}

async function proxyURL(proxyURL, url) {
	const URLs = await ADD(proxyURL);
	const fullURL = URLs[Math.floor(Math.random() * URLs.length)];
	// è§£æžç›®æ ‡ URL
	let parsedURL = new URL(fullURL);
	console.log(parsedURL);
	// æå–å¹¶å¯èƒ½ä¿®æ”¹ URL ç»„ä»¶
	let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
	let URLHostname = parsedURL.hostname;
	let URLPathname = parsedURL.pathname;
	let URLSearch = parsedURL.search;
	// å¤„ç† pathname
	if (URLPathname.charAt(URLPathname.length - 1) == '/') {
		URLPathname = URLPathname.slice(0, -1);
	}
	URLPathname += url.pathname;
	// æž„å»ºæ–°çš„ URL
	let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;
	// åå‘ä»£ç†è¯·æ±‚
	let response = await fetch(newURL);
	// åˆ›å»ºæ–°çš„å“åº”
	let newResponse = new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});
	// æ·»åŠ è‡ªå®šä¹‰å¤´éƒ¨ï¼ŒåŒ…å« URL ä¿¡æ¯
	//newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
	//newResponse.headers.set('X-Original-URL', fullURL);
	newResponse.headers.set('X-New-URL', newURL);
	return newResponse;
}

function é…ç½®ä¿¡æ¯(å¯†ç 
