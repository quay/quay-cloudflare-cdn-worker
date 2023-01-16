/* Handler for requests to CloudFlare. The signature is 
 * passed as a query param `cf_sign` along with the
 * expiry time as `cf_expiry`. We verify the signature
 * first and then check if the request has not expired.
 * Once validated, we fetch the object from S3 and
 * cache the result with a custom cache key which 
 * is the URL 
 * 
 * 
 * **NOTE** Do not split this file into multiple files. 
 * The app-interface/terrform integration require the code
 * to be in a single file
 * */


const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
}

async function handleRequest(request) {
  const url = new URL(request.url);

  // Only use the path for the cache key, removing query strings
  // and always store using HTTPS, for example, https://www.example.com/file-uri-here
  console.log(`got request : ${url}`)

  if (!QUAY_PRIMARY_S3_BUCKET || !QUAY_PRIMARY_REGION) {
    return new Response('Primary origin bucket/region not set', { status: 500 })
  }

  // CORS are required for in-browser requests to the CDN
  // eg: archived build logs
  if (request.method === 'OPTIONS') {
    return handleOptions(request);
  }

  if (url.pathname === '/health') {
    return new Response('ok');
  }

  if (!url.searchParams.has('cf_sign') || !url.searchParams.has('cf_expiry')) {
    return new Response('Missing query parameter', { status: 403 });
  }

  const expiry = Number(url.searchParams.get('cf_expiry'));
  const dataToAuthenticate = `${url.pathname}@${expiry}`;
  const signature = url.searchParams.get('cf_sign');
  const s3_region = url.searchParams.get('region');

  console.log(`data to auth: ${dataToAuthenticate}`);

  const verified = await verifyMessage(signature, dataToAuthenticate);

  if (!verified) {
    const body = 'Invalid Signature';
    return new Response(body, { status: 403 });
  }

  console.log('request verified!!!');

  const now = Date.now() / 1000;

  console.log(`expiry: ${expiry}, now: ${now}`);

  if (now > expiry) {
    const body = `URL expired at ${new Date(expiry)}`;
    return new Response(body, { status: 403 });
  }

  console.log('request not expired!!!')

  const cacheKey = `https://${url.hostname}${url.pathname}`;

  console.log(`cache key : ${cacheKey}`);
  console.log(`fetching object ${url.pathname} from s3`);

  // default to primary bucket
  let origin_s3_bucket = QUAY_PRIMARY_S3_BUCKET;

  if (QUAY_SECONDARY_REGION === s3_region) {
    origin_s3_bucket = QUAY_SECONDARY_S3_BUCKET;
  }

  const s3Host = `${origin_s3_bucket}.s3.amazonaws.com`;

  url.searchParams.delete('cf_expiry')
  url.searchParams.delete('cf_sign')
  url.searchParams.delete('region')
  url.host = s3Host;

  const fetchUrl = url.toString();

  console.log(`fetch URL : ${fetchUrl}`);

  const cacheTtl = CACHE_TTL || 60;

  const rangeHeaderValue = request.headers.get('range');
  console.log(`range header value ${rangeHeaderValue}`);

  const requestHeaders = {};

  if (rangeHeaderValue) {
    requestHeaders['Range'] = rangeHeaderValue;
  }

  let response = await fetch(fetchUrl, {
    cf: {
      cacheTtl: cacheTtl,
      cacheEverything: true,
      cacheKey: cacheKey,
    },
    headers: {
      ...requestHeaders,
    },
  });

  // Reconstruct the Response object to make its headers mutable.
  response = new Response(response.body, response);

  // Set cache control headers to cache on browser for 25 minutes
  response.headers.set('Cache-Control', 'max-age=1500');

  // Set CORS headers
  response.headers.set("Access-Control-Allow-Origin", "*")
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

  return response;
}

function handleOptions(request) {
  const respHeaders = {
    ...corsHeaders,
  }

  if (request.headers.get("Access-Control-Request-Headers") !== null) {
    respHeaders["Access-Control-Allow-Headers"] = request.headers.get("Access-Control-Request-Headers");
  }

  return new Response(null, {
    headers: respHeaders,
  })
}

addEventListener('fetch', event => {
  return event.respondWith(handleRequest(event.request));
});

/******** Signature verification logic *****/

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

