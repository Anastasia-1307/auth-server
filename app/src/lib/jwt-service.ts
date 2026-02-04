import { SignJWT, importPKCS8, importSPKI, jwtVerify } from "jose";
import { prisma } from "./prisma";
import { config } from "./config";
import { generateKeyPairSync, randomUUID } from "crypto";

export interface JWTPayload {
  sub: string;
  email: string;
  name: string;
  role: string;
  aud?: string;
  iss?: string;
  iat?: number;
  exp?: number;
}

let privateKey: CryptoKey | null = null;
let publicKey: CryptoKey | null = null;
let keyId: string | null = null;

async function generateAndSaveKey() {
  console.log("🔑 Generare cheie RSA nouă...");
  
  // Generează chei PEM format
  const { publicKey: pubKey, privateKey: privKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  
  const kid = randomUUID();

  // Dezactivează cheile vechi
  await prisma.auth_keys.updateMany({
    where: { is_active: true },
    data: { is_active: false },
  });

  // Salvează cheia nouă
  await prisma.auth_keys.create({
    data: {
      kid,
      public_key: pubKey,
      private_key: privKey,
      algorithm: "RS256",
      is_active: true,
    },
  });

  console.log("✅ Cheie RSA generată și salvată");
  return { kid, publicKey: pubKey, privateKey: privKey };
}

async function loadKeys() {
  if (privateKey && publicKey && keyId) return;

  let keyRow = await prisma.auth_keys.findFirst({
    where: { is_active: true },
    select: { private_key: true, public_key: true, kid: true }
  });

  // Dacă nu există chei, generează una nouă
  if (!keyRow) {
    const newKey = await generateAndSaveKey();
    keyRow = {
      private_key: newKey.privateKey,
      public_key: newKey.publicKey,
      kid: newKey.kid
    };
  }

  privateKey = await importPKCS8(keyRow.private_key, "RS256");
  publicKey = await importSPKI(keyRow.public_key, "RS256");
  keyId = keyRow.kid;
}

export async function signAccessToken(payload: {
  email: string;
  name: string;
  role: string;
  sub: string;
  audience?: string;
}): Promise<string> {
  await loadKeys();
  
  if (!privateKey || !keyId) throw new Error("Keys not loaded");

  return new SignJWT({
    email: payload.email,
    name: payload.name,
    role: payload.role
  })
    .setProtectedHeader({ alg: "RS256", kid: keyId })
    .setIssuer(config.issuer)
    .setAudience(payload.audience || config.jwtAudience)
    .setIssuedAt()
    .setExpirationTime(config.tokenExpiration)
    .setSubject(payload.sub)
    .sign(privateKey);
}

export async function verifyToken(token: string, audience?: string) {
  await loadKeys();
  
  if (!publicKey) throw new Error("Public key not loaded");

  console.log("🔍 verifyToken - Audience:", audience || config.jwtAudience);
  console.log("🔍 verifyToken - Issuer:", config.issuer);

  const verificationOptions: any = {
    issuer: config.issuer,
    audience: audience || config.jwtAudience,
  };

  console.log("🔍 verifyToken - Options:", verificationOptions);
  console.log("🔍 verifyToken - Public key type:", typeof publicKey);

  try {
    const { payload } = await jwtVerify(token, publicKey, verificationOptions);
    console.log("🔍 verifyToken - Payload received:", payload);
    console.log("🔍 verifyToken - Payload type:", typeof payload);
    return payload as unknown as JWTPayload;
  } catch (err) {
    console.log("❌ verifyToken - JWT verification error:", err);
    throw err;
  }
}
