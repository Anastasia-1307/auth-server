import { Elysia } from "elysia";
import { createOAuthUser, authenticateOAuthUser, validateOAuthClient } from "../services/oauth-service";
import { signAccessToken, verifyToken } from "../lib/jwt-service";
import { renderTemplate } from "../lib/template-engine";
import { generateCode, sha256Base64Url } from "../lib/crypto-utils";
import { config } from "../lib/config";
import { prisma } from "../lib/prisma";
import { randomUUID } from "crypto";

interface AuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  user: { sub: string; email: string; name: string; role: string; };
  expiresAt: number;
}

const authorizationCodes = new Map<string, AuthCode>();

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

    const page = screen === "register" ? "oauth-register" : "oauth-login";
    const url = new URL(`${config.issuer}/${page}`);
    url.searchParams.set("client_id", client_id as string);
    url.searchParams.set("redirect_uri", redirect_uri as string);
    url.searchParams.set("code_challenge", code_challenge as string);
    if (state) url.searchParams.set("state", state as string);
    if (scope) url.searchParams.set("scope", scope as string);

    return redirect(url.toString());
  })

  .get("/oauth-login", async ({ query }) => {
    const clientId = query.client_id?.toString() ?? "";
    const redirectUri = query.redirect_uri?.toString() ?? "";
    const codeChallenge = query.code_challenge?.toString() ?? "";
    const stateValue = query.state?.toString() ?? "";
    const backLink = "http://localhost:3000/login";

    const html = renderTemplate("src/views/oauth-login.html", {
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

  .get("/oauth-register", async ({ query }) => {
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

  .post("/oauth-register", async ({ body, set }) => {
    try {
      const { email, password, username, client_id, redirect_uri, code_challenge, state } = body as any;

      const user = await createOAuthUser({ email, username, password });

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
      url.searchParams.set("client_id", client_id);
      url.searchParams.set("redirect_uri", redirect_uri);
      url.searchParams.set("code_challenge", code_challenge);
      if (state) url.searchParams.set("state", state);

      return new Response(null, {
        status: 302,
        headers: { Location: url.toString() }
      });
    } catch (error) {
      if (error instanceof Error) {
        try {
          const errors = JSON.parse(error.message);
          return {
            status: 400,
            body: { error: errors }
          };
        } catch {
          if (error.message === "Email deja folosit") {
            return {
              status: 400,
              body: { error: { email: error.message } }
            };
          }
        }
      }
      
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  })

  .post("/oauth-login", async ({ body, redirect }) => {
    try {
      const { email, password, client_id, redirect_uri, code_challenge, state } = body as any;
      
      console.log("🔍 /oauth-login - Body:", { email, client_id, redirect_uri, hasCodeChallenge: !!code_challenge });
      console.log("🔍 /oauth-login - Raw code_challenge:", code_challenge);
      console.log("🔍 /oauth-login - Type of code_challenge:", typeof code_challenge);

      if (!email || !password || !client_id || !redirect_uri || !code_challenge) {
        console.log("❌ /oauth-login - Missing required fields");
        return {
          status: 400,
          body: { error: "Missing required fields" }
        };
      }

      console.log("🔍 /oauth-login - Authenticating user:", email);
      const user = await authenticateOAuthUser(email, password);
      console.log("✅ /oauth-login - User authenticated:", user.username, "Role:", user.role);

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
      if (error instanceof Error && error.message === "Credentiale invalide") {
        return {
          status: 401,
          body: { error: error.message }
        };
      }
      
      return {
        status: 500,
        body: { error: "Internal server error" }
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

      authorizationCodes.delete(code);

      console.log("🔍 /token - Generating access token...");
      const accessToken = await signAccessToken({
        email: savedCode.user.email,
        name: savedCode.user.name,
        role: savedCode.user.role ?? "pacient",
        sub: savedCode.user.sub,
        audience: savedCode.clientId
      });
      
      console.log("🔍 /token - Access token generated:", accessToken.substring(0, 20) + "...");

      const response = { access_token: accessToken, token_type: "Bearer", expires_in: 3600 };
      console.log("🔍 /token - Response:", response);
      
      return response;
    } catch (error) {
      console.log("❌ /token - Error:", error);
      set.status = 400;
      return { error: "Missing JSON body or invalid JSON" };
    }
  });
