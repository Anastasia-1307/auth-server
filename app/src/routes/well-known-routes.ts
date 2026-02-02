import { Elysia } from "elysia";
import { importSPKI, exportJWK } from "jose";
import { config } from "../lib/config";
import { prisma } from "../lib/prisma";

export const wellKnownRoutes = new Elysia({ prefix: "/.well-known" })
  .get("/jwks.json", async () => {
    const key = await prisma.auth_keys.findFirst({
      where: { is_active: true },
      select: { public_key: true, kid: true }
    });

    if (!key) return { keys: [] };

    const spkiKey = await importSPKI(key.public_key, "RS256");
    const jwkBase = await exportJWK(spkiKey);
    const jwk = { ...jwkBase, kid: key.kid };

    return { keys: [jwk] };
  })

  .get("/openid-configuration", () => ({
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"]
  }));
