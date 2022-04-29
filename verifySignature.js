

const scopeSign = ["sign", "verify"];

const signAlgorithm = {
  name: "RSASSA-PKCS1-v1_5",
  hash: {
    name: "SHA-256"
  },
  modulusLength: 2048,
  extractable: false,
  publicExponent: new Uint8Array([1, 0, 1])
}

function base64StringToArrayBuffer(b64str) {
  console.log(b64str);
  var byteStr = atob(b64str.trim())
  var bytes = new Uint8Array(byteStr.length)
  for (var i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i)
  }
  return bytes.buffer
}

function textToArrayBuffer(str) {
  var buf = unescape(encodeURIComponent(str)) // 2 bytes for each char
  var bufView = new Uint8Array(buf.length)
  for (var i = 0; i < buf.length; i++) {
    bufView[i] = buf.charCodeAt(i)
  }
  return bufView
}

function arrayBufferToText(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer)
  var str = ''
  for (var i = 0; i < byteArray.byteLength; i++) {
    str += String.fromCharCode(byteArray[i])
  }
  return str
}

function arrayBufferToBase64(arr) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(arr)))
}

function convertBinaryToPem(binaryData, label) {
  var base64Cert = arrayBufferToBase64String(binaryData)
  var pemCert = "-----BEGIN " + label + "-----\r\n"
  var nextIndex = 0
  var lineLength
  while (nextIndex < base64Cert.length) {
    if (nextIndex + 64 <= base64Cert.length) {
      pemCert += base64Cert.substr(nextIndex, 64) + "\r\n"
    } else {
      pemCert += base64Cert.substr(nextIndex) + "\r\n"
    }
    nextIndex += 64
  }
  pemCert += "-----END " + label + "-----\r\n"
  return pemCert
}

function convertPemToBinary(pem) {
  var lines = pem.split('\n')
  var encoded = ''
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].trim().length > 0 &&
      lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
      lines[i].indexOf('-BEGIN PUBLIC KEY-') < 0 &&
      lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
      lines[i].indexOf('-END PUBLIC KEY-') < 0) {
      encoded += lines[i].trim()
    }
  }

  console.log(encoded);
  let decoded = base64StringToArrayBuffer(encoded);
  console.log(decoded);

  return decoded
}

function importPublicKey(pemKey) {
  console.log(`PEM public key ${pemKey}`);

  return new Promise(function (resolve) {
    var importer = crypto.subtle.importKey("spki", convertPemToBinary(pemKey), signAlgorithm, true, ["verify"])
    importer.then(function (key) {
      resolve(key)
    })
  })
}

async function verifyMessage(sig, message) {
    console.log('verifyMessage')
    const decodedSig = base64StringToArrayBuffer(sig)
    const data = textToArrayBuffer(message)

    const publicKeyPem = CLOUDFLARE_PUBLIC_KEY;
    const pub = await importPublicKey(publicKeyPem);
    return await crypto.subtle.verify(signAlgorithm, pub, decodedSig, data)
}

export {verifyMessage};

