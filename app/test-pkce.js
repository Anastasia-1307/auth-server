const { createHash } = require('crypto');

function base64url(input) {
  return input.toString("base64")
    .replace(/\+/g, '-')
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256Base64Url(str) {
  const hash = createHash("sha256").update(str).digest();
  return base64url(hash);
}

const testVerifier = 'a95c4fad167b32682e80cce1e2ba9c756213fa3a999b741974f4b10834653a4b';
console.log('Backend challenge:', sha256Base64Url(testVerifier));
