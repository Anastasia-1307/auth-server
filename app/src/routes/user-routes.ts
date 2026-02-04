import { Elysia } from "elysia";
import { verifyToken, JWTPayload } from "../lib/jwt-service";
import { logResourceAccess, logAuthActivity, logSecurityEvent } from "../services/user-activity-service";
import { config } from "../lib/config";

export const userRoutes = new Elysia()
  .get("/me", async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    console.log("🔍 /me endpoint - Auth header:", auth);
    
    if (!auth || !auth.startsWith("Bearer ")) {
      console.log("❌ Missing or invalid auth header");
      
      // Log unauthorized access attempt
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/me',
        reason: 'Missing or invalid authorization header'
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      return { error: "Unauthorized" };
    }

    const token = auth.slice(7);
    console.log("🔍 Token extracted:", token.substring(0, 20) + "...");

    try {
      console.log("🔍 Verifying token with audience: nextjs_client");
      const payload: JWTPayload = await verifyToken(token, "nextjs_client");
      console.log("🔍 /me - Payload received:", payload);
      console.log("🔍 /me - Payload type:", typeof payload);
      
      if (!payload) {
        console.log("❌ /me - Payload is null/undefined");
        set.status = 401;
        return { error: "Invalid token - no payload" };
      }
      
      console.log("✅ Token verified - User:", payload.email, "Role:", payload.role);

      // Log access to user info
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logResourceAccess(payload.email || 'unknown', 'user_profile', 'access', ipAddress, userAgent);

      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        role: payload.role ?? "pacient"
      };
    } catch (err) {
      console.log("❌ Token verification failed:", err instanceof Error ? err.message : String(err));
      
      // Log unauthorized access attempt with invalid token
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/me',
        reason: 'Invalid or expired token',
        token_preview: token.substring(0, 10) + "..."
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      return { error: "Invalid token" };
    }
  })

  .post("/logout", async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    
    if (!auth || !auth.startsWith("Bearer ")) {
      // Log unauthorized logout attempt
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/logout',
        reason: 'Missing or invalid authorization header'
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      return { error: "Unauthorized" };
    }

    const token = auth.slice(7);

    try {
      const payload: JWTPayload = await verifyToken(token, "nextjs_client");
      
      // Log logout activity
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAuthActivity('logout', payload.email || 'unknown', ipAddress, userAgent);

      return { message: "Logged out successfully" };
    } catch (err) {
      // Log unauthorized logout attempt with invalid token
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logSecurityEvent('unauthorized_access', {
        endpoint: '/logout',
        reason: 'Invalid or expired token',
        token_preview: token.substring(0, 10) + "..."
      }, undefined, ipAddress, userAgent);
      
      set.status = 401;
      return { error: "Invalid token" };
    }
  })

  .get("/health", () => ({ 
    status: "ok", 
    timestamp: new Date().toISOString() 
  }));
