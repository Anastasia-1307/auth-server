import { randomBytes, createHash } from "crypto";

export function base64url(input: Buffer): string {
  // Convert to binary string first, then to base64 (like btoa does)
  let binaryString = '';
  for (const byte of input) {
    binaryString += String.fromCharCode(byte);
  }
  return Buffer.from(binaryString, 'binary').toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function sha256Base64Url(str: string): string {
  // Convert string to bytes like Web Crypto API does
  const data = new TextEncoder().encode(str);
  const hash = createHash("sha256").update(data).digest();
  return base64url(hash);
}

export function generateCode(): string {
  return base64url(randomBytes(32));
}

export function generateRandomString(length: number): string {
  return base64url(randomBytes(Math.ceil(length / 4 * 3))).substring(0, length);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await Bun.password.verify(password, hash);
}
