import { randomBytes, createHash } from "crypto";

export function base64url(input: Buffer): string {
  return input.toString("base64")
    .replace(/\+/g, '-')
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function sha256Base64Url(str: string): string {
  const hash = createHash("sha256").update(str).digest();
  return base64url(hash);
}

export function generateCode(): string {
  return base64url(randomBytes(32));
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await Bun.password.verify(password, hash);
}
