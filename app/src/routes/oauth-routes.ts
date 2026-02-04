import { Elysia } from "elysia";
import { createOAuthUser, authenticateOAuthUser, validateOAuthClient } from "../services/oauth-service";
import { signAccessToken, verifyToken } from "../lib/jwt-service";
import { renderTemplate } from "../lib/template-engine";
import { generateCode, sha256Base64Url } from "../lib/crypto-utils";
import { config } from "../lib/config";
import { prisma } from "../lib/prisma";
import { randomUUID } from "crypto";
import { logAuthActivity, logResourceAccess, logFailedOAuthActivity } from "../services/user-activity-service";

interface AuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  user: { sub: string; email: string; name: string; role: string; };
  expiresAt: number;
}

const authorizationCodes = new Map<string, AuthCode>();

// Sync OAuth user to resource server
async function syncOAuthUserToResourceServer(user: any) {
  try {
    const resourceServerUrl = process.env.RESOURCE_SERVER_URL || "http://localhost:5000";
    
    const response = await fetch(`${resourceServerUrl}/api/sync/oauth-user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role || "pacient"
      })
    });

    if (!response.ok) {
      console.error("❌ Failed to sync OAuth user to resource server:", await response.text());
    } else {
      console.log("✅ OAuth user synced to resource server:", user.email);
    }
  } catch (error) {
    console.error("❌ Error syncing OAuth user to resource server:", error);
  }
}

export const oauthRoutes = new Elysia()
  .get("/authorize", async ({ query, redirect }) => {
    const { client_id, redirect_uri, response_type, code_challenge, state, scope, screen } = query;

    if (response_type !== "code") {
      return {
        status: 400,
        body: { error: "Unsupported response_type" }
      };
    }

    try {
      await validateOAuthClient(client_id as string, redirect_uri as string);
    } catch (error) {
      return {
        status: 400,
        body: { error: "Unsupported redirect_uri" }
      };
    }

    const page = screen === "register" ? "oauth-login" : "oauth-login";
    const url = new URL(`${config.issuer}/oauth/login`);
    url.searchParams.set("client_id", client_id as string);
    url.searchParams.set("redirect_uri", redirect_uri as string);
    url.searchParams.set("code_challenge", code_challenge as string);
    if (state) url.searchParams.set("state", state as string);
    if (scope) url.searchParams.set("scope", scope as string);

    return redirect(url.toString());
  })

  .get("/oauth/register", async ({ query }) => {
    const clientId = String(query.client_id ?? "");
    const redirectUri = String(query.redirect_uri ?? "");
    const codeChallenge = String(query.code_challenge ?? "");
    const stateValue = String(query.state ?? "");
    const backLink = "http://localhost:3000/register";

    const html = renderTemplate("src/views/oauth-register.html", {
      clientId,
      redirectUri,
      codeChallenge,
      state: stateValue,
      backLink
    });

    return new Response(html, {
      headers: { "Content-Type": "text/html; charset=UTF-8" }
    });
  })

  .post("/oauth-register", async ({ body, set, request }) => {
    try {
      const { email, password, username, client_id, redirect_uri, code_challenge, state } = body as any;

      const user = await createOAuthUser({ email, username, password });

      // Log OAuth registration activity
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAuthActivity('register', email, ipAddress, userAgent);
      await logResourceAccess(email, 'oauth', 'register', ipAddress, userAgent, { client_id });

      const authCode = generateCode();
      console.log("🔍 /oauth-register - Generated code:", authCode);
      console.log("🔍 /oauth-register - Code challenge:", code_challenge);
      
      authorizationCodes.set(authCode, {
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        user: { sub: randomUUID(), email, name: user.username, role: user.role ?? "pacient" },
        expiresAt: Date.now() + config.codeExpiration
      });
      
      console.log("🔍 /oauth-register - Code saved, total codes:", authorizationCodes.size);

      const url = new URL(`${config.issuer}/oauth-login`);
      url.searchParams.set("code", authCode);
      url.searchParams.set("state", state);
      
      console.log("🔍 /oauth-register - Redirecting to:", url.toString());

      return new Response(null, {
        status: 302,
        headers: { Location: url.toString() }
      });
    } catch (error) {
      console.log("❌ /oauth-register - Error:", error);
      console.log("❌ /oauth-register - Error type:", typeof error);
      console.log("❌ /oauth-register - Error message:", error instanceof Error ? error.message : 'Not an Error object');
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      const { email } = body as any;
      
      if (error instanceof Error) {
        try {
          const errors = JSON.parse(error.message);
          console.log("🔍 /oauth-register - About to log validation failed activity for:", email);
          await logFailedOAuthActivity('register_failed', email || 'unknown', 'Validation errors', ipAddress, userAgent);
          console.log("✅ /oauth-register - Validation failed activity logged");
          return {
            status: 400,
            body: { error: errors }
          };
        } catch {
          if (error.message === "Email deja folosit") {
            console.log("🔍 /oauth-register - About to log email exists failed activity for:", email);
            await logFailedOAuthActivity('register_failed', email || 'unknown', 'Email already exists', ipAddress, userAgent);
            console.log("✅ /oauth-register - Email exists failed activity logged");
            return {
              status: 400,
              body: { error: { email: error.message } }
            };
          }
        }
      }
      
      console.log("🔍 /oauth-register - About to log generic failed activity for:", email);
      await logFailedOAuthActivity('register_failed', email || 'unknown', 'Internal server error', ipAddress, userAgent);
      console.log("✅ /oauth-register - Generic failed activity logged");
      return {
        status: 500,
        body: { error: "Eroare internă de server" }
      };
    }
  })

  .post("/oauth-login", async ({ body, redirect, request }) => {
    try {
      const { email, password, client_id, redirect_uri, code_challenge, state } = body as any;
      
      console.log("🔍 /oauth-login - Body:", { email, client_id, redirect_uri, hasCodeChallenge: !!code_challenge });
      console.log("🔍 /oauth-login - Raw code_challenge:", code_challenge);
      console.log("🔍 /oauth-login - Type of code_challenge:", typeof code_challenge);

      console.log("🔍 /oauth-login - Body received:", { email, password, client_id, redirect_uri, code_challenge, state });
      
      if (!email || !password || !client_id || !redirect_uri || !code_challenge) {
        console.log("❌ /oauth-login - Missing required fields:");
        console.log("  - email:", !!email);
        console.log("  - password:", !!password);
        console.log("  - client_id:", !!client_id);
        console.log("  - redirect_uri:", !!redirect_uri);
        console.log("  - code_challenge:", !!code_challenge);
        return {
          status: 400,
          body: { error: "Missing required fields" }
        };
      }

      console.log("🔍 /oauth-login - Authenticating user:", email);
      
      let user;
      try {
        user = await authenticateOAuthUser(email, password);
        console.log("✅ /oauth-login - User authenticated:", user.username, "Role:", user.role);
      } catch (authError) {
        console.log("❌ /oauth-login - Authentication failed:", authError);
        console.log("❌ /oauth-login - Auth error type:", typeof authError);
        console.log("❌ /oauth-login - Auth error message:", authError instanceof Error ? authError.message : 'Not an Error object');
        
        const ipAddress = request.headers.get("x-forwarded-for") || 
                         request.headers.get("x-real-ip") || 
                         "unknown";
        const userAgent = request.headers.get("user-agent") || "unknown";
        
        if (authError instanceof Error && authError.message === "Credentiale invalide") {
          console.log("🔍 /oauth-login - About to log failed activity for:", email);
          await logFailedOAuthActivity('login_failed', email || 'unknown', 'Invalid credentials', ipAddress, userAgent);
          console.log("✅ /oauth-login - Failed activity logged");
          return {
            status: 401,
            body: { error: authError.message }
          };
        }
        
        console.log("🔍 /oauth-login - About to log generic failed activity for:", email);
        await logFailedOAuthActivity('login_failed', email || 'unknown', 'Internal server error', ipAddress, userAgent);
        console.log("✅ /oauth-login - Generic failed activity logged");
        return {
          status: 500,
          body: { error: "Eroare internă de server" }
        };
      }

      // Log OAuth login activity
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAuthActivity('login', email, ipAddress, userAgent);
      await logResourceAccess(email, 'oauth', 'login', ipAddress, userAgent, { client_id });

      const authCode = generateCode();
      console.log("🔍 /oauth-login - Generated code:", authCode);
      
      authorizationCodes.set(authCode, {
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        user: { sub: randomUUID(), email, name: user.username, role: user.role ?? "pacient" },
        expiresAt: Date.now() + config.codeExpiration
      });
      
      console.log("🔍 /oauth-login - Code saved with challenge:", code_challenge);
      console.log("🔍 /oauth-login - Total codes:", authorizationCodes.size);

      const separator = redirect_uri.includes("?") ? "&" : "?";
      const redirectTo = `${redirect_uri}${separator}code=${authCode}${state ? `&state=${state}` : ""}`;
      
      console.log("🔍 /oauth-login - Redirecting to:", redirectTo);

      return redirect(redirectTo);
    } catch (error) {
      console.log("❌ /oauth-login - Error:", error);
      console.log("❌ /oauth-login - Error type:", typeof error);
      console.log("❌ /oauth-login - Error message:", error instanceof Error ? error.message : 'Not an Error object');
      
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      const { email } = body as any;
      
      if (error instanceof Error && error.message === "Credentiale invalide") {
        console.log("🔍 /oauth-login - About to log failed activity for:", email);
        await logFailedOAuthActivity('login_failed', email || 'unknown', 'Invalid credentials', ipAddress, userAgent);
        console.log("✅ /oauth-login - Failed activity logged");
        return {
          status: 401,
          body: { error: error.message }
        };
      }
      
      console.log("🔍 /oauth-login - About to log generic failed activity for:", email);
      await logFailedOAuthActivity('login_failed', email || 'unknown', 'Internal server error', ipAddress, userAgent);
      console.log("✅ /oauth-login - Generic failed activity logged");
      return {
        status: 500,
        body: { error: "Eroare internă de server" }
      };
    }
  })

  .post("/token", async ({ request, set }) => {
    try {
      const body = await request.json();
      console.log("🔍 /token endpoint - Body:", body);
      
      const { grant_type, code, client_id, code_verifier } = body;

      if (!grant_type || !code || !client_id || !code_verifier) {
        console.log("❌ /token - Missing required fields");
        set.status = 400;
        return { error: "Missing required fields" };
      }

      if (grant_type !== "authorization_code") {
        console.log("❌ /token - Unsupported grant_type:", grant_type);
        return { status: 400, body: { error: "Unsupported grant_type" } };
      }

      const savedCode = authorizationCodes.get(code);
      console.log("🔍 /token - Saved code exists:", !!savedCode);
      
      if (!savedCode) {
        console.log("❌ /token - Invalid grant - code not found");
        return { status: 400, body: { error: "Invalid grant" } };
      }

      if (savedCode.expiresAt < Date.now()) {
        console.log("❌ /token - Code expired");
        authorizationCodes.delete(code);
        return { status: 400, body: { error: "Invalid grant, code expired" } };
      }

      const challenge = sha256Base64Url(code_verifier);
      console.log("🔍 /token - PKCE details:");
      console.log("  - Code verifier (first 20):", code_verifier.substring(0, 20) + "...");
      console.log("  - Generated challenge:", challenge);
      console.log("  - Saved challenge:", savedCode.codeChallenge);
      console.log("  - Match:", challenge === savedCode.codeChallenge);
      
      if (challenge !== savedCode.codeChallenge) {
        console.log("❌ /token - PKCE verification failed");
        return { status: 400, body: { error: "Invalid grant, PKCE verification failed" } };
      }

      if (client_id !== savedCode.clientId) {
        console.log("❌ /token - Invalid client");
        return { status: 400, body: { error: "Invalid client" } };
      }

      // Log token exchange activity
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logResourceAccess(savedCode.user.email, 'oauth', 'token_exchange', ipAddress, userAgent, { 
        client_id, 
        email: savedCode.user.email 
      });

      authorizationCodes.delete(code);

      console.log("🔍 /token - Generating access token...");
      const accessToken = await signAccessToken({
        email: savedCode.user.email,
        name: savedCode.user.name,
        role: savedCode.user.role ?? "pacient",
        sub: savedCode.user.sub,
        audience: "nextjs_client"
      });
      
      console.log("🔍 /token - Access token generated:", accessToken.substring(0, 20) + "...");

      // Sync OAuth user to resource server
      await syncOAuthUserToResourceServer({
        id: savedCode.user.sub,
        email: savedCode.user.email,
        username: savedCode.user.name,
        role: savedCode.user.role ?? "pacient"
      });

      const response = { access_token: accessToken, token_type: "Bearer", expires_in: 3600 };
      console.log("🔍 /token - Response:", response);
      
      return response;
    } catch (error) {
      console.log("❌ /token - Error:", error);
      set.status = 400;
      return { error: "Missing JSON body or invalid JSON" };
    }
  });
