/* Handler for requests to CloudFlare. The signature is 
 * passed as a query param `signature` along with the
 * expiry time as `expiry`. We verify the signature
 * first and then check if the request not expired.
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

  const verified = await verifyMessage(dataToAuthenticate, signature);

  if (!verified) {
    const body = 'Invalid Signature';
    return new Response(body, { status: 403 });
  } 

  if (Date.now() > expiry) {
    const body = `URL expired at ${new Date(expiry)}`;
    return new Response(body, { status: 403 });
  } */

  const cacheKey = `https://${url.hostname}${url.pathname}`;

  console.log(`cache key : ${cacheKey}`);

  // TODO: Add S3 specific logic for fetching
  console.log(`fetching object ${url.pathname} from s3`);

  const s3Bucket = "cloudflare-poc-quay-storage";

  const s3Host = `${s3Bucket}.s3.amazonaws.com`;

  url.searchParams.delete('cf_expiry')
  url.searchParams.delete('cf_sign')
  url.host = s3Host;

  const fetchUrl = url.toString();

  console.log(`fetch URL : ${fetchUrl}`);

  let response = await fetch(fetchUrl, {
    cf: {
      // Always cache this fetch regardless of content type
      // for a max of 5 seconds before revalidating the resource
      cacheTtl: 50,
      cacheEverything: true,
      //Enterprise only feature, see Cache API for other plans
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
