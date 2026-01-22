import { Elysia, t } from "elysia";
import { cookie } from "@elysiajs/cookie";
import { html } from "@elysiajs/html";
import { randomBytes, createHash } from "crypto";
import dotenv from 'dotenv';
import { SignJWT, importPKCS8 } from "jose";
import postgres from "postgres";
import { cors } from '@elysiajs/cors';

dotenv.config();

const sql = postgres({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME,
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

interface AuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  user: { sub: string; email: string; name: string; };
  expiresAt: number;
}

const ISSUER = "http://localhost:4000";
const [keyRow] = await sql`
  SELECT private_key, kid
  FROM auth_keys
  WHERE is_active = true
    LIMIT 1
`;

if (!keyRow) throw new Error("Nu există cheie RSA activă în DB");

const PRIVATE_KEY_PEM = keyRow.private_key;
const KEY_ID = keyRow.kid;

const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

const authorizationCodes = new Map<string, AuthCode>();

function base64url(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, '-').replace(/\//g, "_").replace(/=+$/g, "");
}

function sha256Base64Url(str: string): string {
  const hash = createHash("sha256").update(str).digest();
  return base64url(hash);
}

function generateCode() {
  return base64url(randomBytes(32));
}

async function verifyPassword(password: string, hash: string) {
  return await Bun.password.verify(password, hash);
}

const app = new Elysia()
    .use(cookie())
    .use(html())
    .use(cors({
      origin: 'http://localhost:3000',
      credentials: true,
      allowedHeaders: ['Content-Type', 'Authorization']
    }))

    // --- FIX: Endpoint /authorize (standard OAuth2) ---
    .get("/authorize", async ({ query, redirect, set }) => {
      const {
        client_id,
        redirect_uri,
        response_type,
        code_challenge,
        state,
        scope,
        screen
      } = query;

      // 1️⃣ Validare response_type
      if (response_type !== "code") {
        set.status = 400;
        return { error: "unsupported_response_type" };
      }

      // 2️⃣ Validare client_id + redirect_uri
      const [client] = await sql`
        SELECT redirect_uris
        FROM oauth_clients
        WHERE client_id = ${client_id}
      `;

      if (!client || !client.redirect_uris.includes(redirect_uri)) {
        set.status = 400;
        return { error: "invalid_redirect_uri" };
      }

      // 3️⃣ Alegere ecran login / register
      const page = screen === "register"
          ? "oauth-register"
          : "oauth-login";

      // 4️⃣ Redirect către pagina de login
      const url = new URL(`http://localhost:4000/${page}`);
      url.searchParams.set("client_id", client_id as string);
      url.searchParams.set("redirect_uri", redirect_uri as string);
      url.searchParams.set("code_challenge", code_challenge as string);

      if (state) url.searchParams.set("state", state as string);
      if (scope) url.searchParams.set("scope", scope as string);

      return redirect(url.toString());
    })
    // --- OAuth login fictiv GET ---
    .get("/oauth-login", ({ query }) => {
      const { client_id, redirect_uri, code_challenge, state, scope } = query;

      return `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login - OAuth Server</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
          }
          .login-container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
          }
          h2 {
            margin-top: 0;
            color: #333;
            text-align: center;
          }
          .form-group {
            margin-bottom: 20px;
          }
          label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
          }
          input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            box-sizing: border-box;
          }
          input:focus {
            outline: none;
            border-color: #667eea;
          }
          button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
          }
          button:hover {
            background: #5568d3;
          }
          .info {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #666;
          }
          .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            display: none;
          }
        </style>
      </head>
      <body>
        <div class="login-container">
          <h2>🔐 OAuth Login</h2>
          
          <div class="info">
            <strong>Client:</strong> ${client_id || 'Unknown'}<br>
            <strong>Scope:</strong> ${scope || 'profile email'}
          </div>
          
          <div class="error" id="error"></div>
          
          <form action="/oauth-login" method="POST">
            <input type="hidden" name="client_id" value="${client_id || ''}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}" />
            <input type="hidden" name="code_challenge" value="${code_challenge || ''}" />
            <input type="hidden" name="state" value="${state || ''}" />
            
            <div class="form-group">
              <label>Email</label>
              <input name="email" type="email" autocomplete="off" required />
            </div>
            
            <div class="form-group">
              <label>Parolă</label>
              <input name="password" type="password" autocomplete="off"  required />
            </div>
            
            <button type="submit">Conectare</button>
          </form>
          
          <div style="margin-top: 20px; text-align: center; font-size: 12px; color: #999;">
            OAuth 2.0 + PKCE Server
          </div>
        </div>
      </body>
      </html>
    `;
    })
    .get("/oauth-register", ({ query }) => {
      const { client_id, redirect_uri, code_challenge, state, scope } = query;
      const { error } = query;

      const errorMessages: Record<string, string> = {
        email_invalid: "Email-ul nu este valid",
        password_short: "Parola trebuie să aibă minim 8 caractere",
        username_short: "Numele trebuie să aibă minim 3 caractere",
        email_exists: "Există deja un cont cu acest email"
      };

      const errorHtml = error
          ? `<div class="error">${errorMessages[error as string] || "Eroare necunoscută"}</div>`
          : "";
      return `
  <!DOCTYPE html>
  <html>
  <head>
    <title>Register - OAuth Server</title>
    <style>
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0;
      }
      .login-container {
        background: white;
        padding: 40px;
        border-radius: 12px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        width: 100%;
        max-width: 400px;
      }
      h2 {
        margin-top: 0;
        color: #333;
        text-align: center;
      }
      .form-group {
        margin-bottom: 20px;
      }
      label {
        display: block;
        margin-bottom: 5px;
        color: #555;
        font-weight: 500;
      }
      input {
        width: 100%;
        padding: 12px;
        border: 1px solid #ddd;
        border-radius: 6px;
        font-size: 14px;
        box-sizing: border-box;
      }
      input:focus {
        outline: none;
        border-color: #667eea;
      }
      button {
        width: 100%;
        padding: 12px;
        background: #667eea;
        color: white;
        border: none;
        border-radius: 6px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.3s;
      }
      button:hover {
        background: #5568d3;
      }
      .info {
        background: #f8f9fa;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 20px;
        font-size: 13px;
        color: #666;
      }
   
  .error {
    background: #fee;
    color: #c33;
    padding: 12px;
    border-radius: 6px;
    margin-bottom: 20px;
    font-size: 14px;
  }
</style>


  </head>
  <body>
    <div class="login-container">
      <h2>📝 Creează cont OAuth</h2>

      <div class="info">
        <strong>Client:</strong> ${client_id || "Unknown"}<br>
        <strong>Scope:</strong> ${scope || "profile email"}
        ${errorHtml}
      </div>

      <form action="/oauth-register" method="POST">
        <input type="hidden" name="client_id" value="${client_id || ""}" />
        <input type="hidden" name="redirect_uri" value="${redirect_uri || ""}" />
        <input type="hidden" name="code_challenge" value="${code_challenge || ""}" />
        <input type="hidden" name="state" value="${state || ""}" />

        <div class="form-group">
          <label>Nume complet</label>
          <input name="username" autocomplete="off"  required />
        </div>

        <div class="form-group">
          <label>Email</label>
          <input name="email" type="email" autocomplete="off"  required />
        </div>

        <div class="form-group">
          <label>Parolă</label>
          <input name="password" type="password" autocomplete="off" required />
        </div>

        <button type="submit">Creează cont</button>
      </form>

      <div style="margin-top: 20px; text-align: center; font-size: 12px; color: #999;">
        OAuth 2.0 + PKCE Server
      </div>
    </div>
  </body>
  </html>
  `;
    })
    .post("/oauth-register", async ({ body, redirect, set }) => {
      const {
        email,
        password,
        username,
        client_id,
        redirect_uri,
        code_challenge,
        state
      } = body as any;

      const baseRedirect =
          `/oauth-register?client_id=${encodeURIComponent(client_id)}`
          + `&redirect_uri=${encodeURIComponent(redirect_uri)}`
          + `&code_challenge=${encodeURIComponent(code_challenge)}`
          + (state ? `&state=${state}` : "");

      // 🔴 VALIDARE PRIETENOASĂ
      if (!email?.includes("@")) {
        return redirect(`${baseRedirect}&error=email_invalid`);
      }

      if (!password || password.length < 8) {
        return redirect(`${baseRedirect}&error=password_short`);
      }

      if (!username || username.length < 3) {
        return redirect(`${baseRedirect}&error=username_short`);
      }

      // verificare user existent
      const [existing] = await sql`
    SELECT id FROM oauth_users WHERE email = ${email}
  `;
      if (existing) {
        return redirect(`${baseRedirect}&error=email_exists`);
      }

      // Hash password
      const passwordHash = await Bun.password.hash(password, { algorithm: "argon2id" });

      // Creează contul
      const [user] = await sql`
    INSERT INTO oauth_users (email, username, password_hash)
    VALUES (${email}, ${username}, ${passwordHash})
    RETURNING id, email, username
  `;

      // Generează authorization code
      const authCode = generateCode();
      authorizationCodes.set(authCode, {
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        user: {
          sub: user.id.toString(),
          email: user.email,
          name: user.username
        },
        expiresAt: Date.now() + 5 * 60 * 1000
      });

      const separator = redirect_uri.includes("?") ? "&" : "?";
      return redirect(`${redirect_uri}${separator}code=${authCode}${state ? `&state=${state}` : ""}`);
    }, {
      body: t.Object({
        email: t.String({ format: "email" }),
        password: t.String({ minLength: 8 }),
        username: t.String({ minLength: 3 }),
        client_id: t.String(),
        redirect_uri: t.String(),
        code_challenge: t.String(),
        state: t.Optional(t.String())
      })
    })
    // --- OAuth login fictiv POST ---
    .post("/oauth-login", async ({ body, set, redirect }) => {
      const { email, password, client_id, redirect_uri, code_challenge, state } = body as {
        email: string;
        password: string;
        client_id: string;
        redirect_uri: string;
        code_challenge: string;
        state?: string;
      };

      // Validare
      if (!email || !password || !client_id || !redirect_uri || !code_challenge) {
        set.status = 400;
        return { error: "Missing required fields" };
      }

      // Verificare user în DB
      const [user] = await sql`
      SELECT id, password_hash, username 
      FROM oauth_users 
      WHERE email = ${email}
    `;

      if (!user || !(await verifyPassword(password, user.password_hash))) {
        set.status = 401;
        return { error: "Credentiale invalide" };
      }

      // Generare authorization code
      const authCode = generateCode();
      authorizationCodes.set(authCode, {
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        user: {
          sub: user.id.toString(),
          email,
          name: user.username
        },
        expiresAt: Date.now() + 5 * 60 * 1000 // 5 minute
      });

      console.log(`✅ Authorization code generat: ${authCode.substring(0, 10)}...`);
      console.log(`   User: ${email}`);
      console.log(`   Redirect: ${redirect_uri}`);

      // Redirecționare către client cu code
      const separator = redirect_uri.includes("?") ? "&" : "?";
      return redirect(`${redirect_uri}${separator}code=${authCode}${state ? `&state=${state}` : ""}`);
    }, {
      body: t.Object({
        email: t.String({ format: "email" }),
        password: t.String({ minLength: 1 }),
        client_id: t.String(),
        redirect_uri: t.String(),
        code_challenge: t.String(),
        state: t.Optional(t.String())
      })
    })

    // --- Token endpoint ---
    .post("/token", async ({ body, set }) => {
      const { grant_type, code, client_id, code_verifier, redirect_uri } = body as {
        grant_type: string;
        code: string;
        client_id: string;
        code_verifier: string;
        redirect_uri?: string;
      };

      console.log('📥 Token request:', { grant_type, code: code?.substring(0, 10) + '...', client_id });

      if (grant_type !== 'authorization_code') {
        set.status = 400;
        return { error: "unsupported_grant_type" };
      }

      const savedCode = authorizationCodes.get(code);
      if (!savedCode) {
        console.error('❌ Code not found');
        set.status = 400;
        return { error: "invalid_grant", detail: "Code not found or already used" };
      }

      if (savedCode.expiresAt < Date.now()) {
        console.error('❌ Code expired');
        authorizationCodes.delete(code);
        set.status = 400;
        return { error: "invalid_grant", detail: "Code expired" };
      }

      // Verificare PKCE
      const challenge = sha256Base64Url(code_verifier);
      if (challenge !== savedCode.codeChallenge) {
        console.error('❌ PKCE verification failed');
        set.status = 400;
        return { error: "invalid_grant", detail: "PKCE verification failed" };
      }

      // Verificare client_id
      if (client_id !== savedCode.clientId) {
        console.error('❌ Client ID mismatch');
        set.status = 400;
        return { error: "invalid_client" };
      }

      // Șterge codul (one-time use)
      authorizationCodes.delete(code);

      // Generare JWT access token
      const accessToken = await new SignJWT({
        email: savedCode.user.email,
        name: savedCode.user.name
      })
          .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
          .setIssuedAt()
          .setIssuer(ISSUER)
          .setAudience(savedCode.clientId)
          .setExpirationTime("1h")
          .setSubject(savedCode.user.sub)
          .sign(privateKey);

      console.log('✅ Access token generat pentru user:', savedCode.user.email);

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600
      };
    })

    // --- JWKS endpoint (pentru validarea tokenurilor) ---
    .get("/.well-known/jwks.json", async () => {
      const [keyRow] = await sql`
      SELECT public_key_jwk 
      FROM auth_keys 
      WHERE is_active = true 
      LIMIT 1
    `;

      if (!keyRow) {
        return { keys: [] };
      }

      return { keys: [JSON.parse(keyRow.public_key_jwk)] };
    })

    // --- OpenID Configuration endpoint ---
    .get("/.well-known/openid-configuration", () => {
      return {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"]
      };
    })

    // --- Health check ---
    .get("/health", () => ({
      status: "ok",
      timestamp: new Date().toISOString()
    }))

    .listen(4000, ({ hostname, port }) => {
      console.log(`🚀 Auth Server rulează pe http://${hostname}:${port}`);
      console.log(`📋 Endpoints disponibile:`);
      console.log(`   - GET  /authorize`);
      console.log(`   - POST /token`);
      console.log(`   - GET  /.well-known/openid-configuration`);
      console.log(`   - GET  /.well-known/jwks.json`);
    });