/* Handler for requests to CloudFlare. The signature is 
 * passed as a query param `cf_sign` along with the
 * expiry time as `cf_expiry`. We verify the signature
 * first and then check if the request has not expired.
 * Once validated, we fetch the object from S3 and
 * cache the result with a custom cache key which 
 * is the URL 
 * */

import {verifyMessage} from './verifySignature.js';

async function handleRequest(request) {
  const url = new URL(request.url);

  // Only use the path for the cache key, removing query strings
  // and always store using HTTPS, for example, https://www.example.com/file-uri-here
  console.log(`got request : ${url}`)
  if (!url.searchParams.has('cf_sign') || !url.searchParams.has('cf_expiry')) {
    return new Response('Missing query parameter', { status: 403 });
  }

  const expiry = Number(url.searchParams.get('cf_expiry'));
  const dataToAuthenticate = `${url.pathname}@${expiry}`;
  const signature = url.searchParams.get('cf_sign')

  console.log(`data to auth: ${dataToAuthenticate}`);

  const verified = await verifyMessage(signature, dataToAuthenticate);

  if (!verified) {
    const body = 'Invalid Signature';
    return new Response(body, { status: 403 });
  } 

  console.log('request verified!!!');

  const now = Date.now()/1000;

  console.log(`expiry: ${expiry}, now: ${now}`);

  if (now > expiry) {
    const body = `URL expired at ${new Date(expiry)}`;
    return new Response(body, { status: 403 });
  } 
  
  console.log('request not expired!!!')


  const cacheKey = `https://${url.hostname}${url.pathname}`;

  console.log(`cache key : ${cacheKey}`);
  console.log(`fetching object ${url.pathname} from s3`);

  const s3Host = `${QUAY_S3_BUCKET}.s3.amazonaws.com`;

  url.searchParams.delete('cf_expiry')
  url.searchParams.delete('cf_sign')
  url.host = s3Host;

  const fetchUrl = url.toString();

  console.log(`fetch URL : ${fetchUrl}`);

  const cacheTtl = CACHE_TTL || 60;

  let response = await fetch(fetchUrl, {
    cf: {
      cacheTtl: cacheTtl,
      cacheEverything: true,
      cacheKey: cacheKey,
    },
  });

  // Reconstruct the Response object to make its headers mutable.
  response = new Response(response.body, response);

  // Set cache control headers to cache on browser for 25 minutes
  response.headers.set('Cache-Control', 'max-age=1500');
  return response;
}

addEventListener('fetch', event => {
  return event.respondWith(handleRequest(event.request));
});
