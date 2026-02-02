import { Elysia } from "elysia";
import { verifyToken } from "../lib/jwt-service";
import { config } from "../lib/config";

export const userRoutes = new Elysia()
  .get("/me", async ({ request, set }) => {
    const auth = request.headers.get("authorization");
    console.log("🔍 /me endpoint - Auth header:", auth);
    
    if (!auth || !auth.startsWith("Bearer ")) {
      console.log("❌ Missing or invalid auth header");
      set.status = 401;
      return { error: "Unauthorized" };
    }

    const token = auth.slice(7);
    console.log("🔍 Token extracted:", token.substring(0, 20) + "...");

    try {
      console.log("🔍 Verifying token with audience: nextjs_client");
      const payload = await verifyToken(token, "nextjs_client");
      console.log("🔍 /me - Payload received:", payload);
      console.log("🔍 /me - Payload type:", typeof payload);
      
      if (!payload) {
        console.log("❌ /me - Payload is null/undefined");
        set.status = 401;
        return { error: "Invalid token - no payload" };
      }
      
      console.log("✅ Token verified - User:", payload.email, "Role:", payload.role);

      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        role: payload.role ?? "pacient"
      };
    } catch (err) {
      console.log("❌ Token verification failed:", err instanceof Error ? err.message : String(err));
      set.status = 401;
      return { error: "Invalid token" };
    }
  })

  .get("/health", () => ({ 
    status: "ok", 
    timestamp: new Date().toISOString() 
  }));
