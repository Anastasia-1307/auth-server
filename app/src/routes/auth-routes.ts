import { Elysia, t } from "elysia";
import { createUser, authenticateUser } from "../services/auth-service";
import { signAccessToken } from "../lib/jwt-service";
import { logAuthActivity, logFailedAuthActivity } from "../services/user-activity-service";
import { config } from "../lib/config";

export const authRoutes = new Elysia({ prefix: "/auth" })
  .post("/register", async ({ body, set, request }) => {
    try {
      console.log("🔍 Register request received:", body);
      
      const { email, username, password } = body as any;
      
      console.log("🔍 Creating user:", { email, username });
      const user = await createUser({ email, username, password });
      const userRole = user.role ?? "pacient";
      
      console.log("✅ User created successfully:", { id: user.id, email: user.email, role: userRole });
      
      // Log registration activity
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      console.log("🔍 Logging auth activity...");
      await logAuthActivity('register', email, ipAddress, userAgent);
      
      // Generează token automat la înregistrare
      console.log("🔍 Generating access token...");
      const accessToken = await signAccessToken({
        email: user.email,
        name: user.username,
        role: userRole,
        sub: user.id.toString()
      });
      
      console.log("✅ Token generated successfully");
      
      set.status = 201;
      return {
        token: accessToken,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: userRole
        }
      };
    } catch (error) {
      console.error("❌ Register error:", error);
      // Log registration failures
      const { email } = body as any;
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      if (error instanceof Error) {
        try {
          const errors = JSON.parse(error.message);
          await logFailedAuthActivity('register_failed', email, 'Validation errors', ipAddress, userAgent);
          set.status = 400;
          return { error: errors };
        } catch {
          if (error.message === "Email deja folosit") {
            await logFailedAuthActivity('register_failed', email, 'Email already exists', ipAddress, userAgent);
            set.status = 409;
            return { error: error.message };
          }
        }
      }
      
      await logFailedAuthActivity('register_failed', email, 'Internal server error', ipAddress, userAgent);
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  })

  .post("/login", async ({ body, set, request }) => {
    try {
      const { email, password } = body as { email: string; password: string };

      if (!email || !password) {
        set.status = 400;
        return { error: "Trebuie completate toate câmpurile" };
      }

      const user = await authenticateUser(email, password);
      const userRole = user.role ?? "pacient";

      // Log login activity
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      await logAuthActivity('login', email, ipAddress, userAgent);

      const accessToken = await signAccessToken({
        email: user.email,
        name: user.username,
        role: userRole,
        sub: user.id.toString()
      });

      return {
        token: accessToken,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: userRole
        }
      };
    } catch (error) {
      // Log login failures - extract email from body
      const { email } = body as { email: string; password: string };
      const ipAddress = request.headers.get("x-forwarded-for") || 
                       request.headers.get("x-real-ip") || 
                       "unknown";
      const userAgent = request.headers.get("user-agent") || "unknown";
      
      if (error instanceof Error && error.message === "Credentiale invalide") {
        await logFailedAuthActivity('login_failed', email, 'Invalid credentials', ipAddress, userAgent);
        set.status = 401;
        return { error: error.message };
      }
      
      await logFailedAuthActivity('login_failed', email, 'Internal server error', ipAddress, userAgent);
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  });
