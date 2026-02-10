import { Elysia, t } from "elysia";
import { createUser, authenticateUser } from "../services/auth-service";
import { signAccessToken } from "../lib/jwt-service";
import { logAuthActivity, logFailedAuthActivity } from "../services/user-activity-service";
import { PasswordResetService } from "../services/password-reset-service";
import { EmailService } from "../services/email-service";
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
  })

  // Request password reset
  .post("/request-password-reset", async ({ body, request, set }) => {
    console.log("🔍 === PASSWORD RESET REQUEST START ===");
    console.log("🔍 Request method:", request.method);
    console.log("🔍 Request URL:", request.url);
    console.log("🔍 Request headers:", Object.fromEntries(request.headers.entries()));
    console.log("🔍 Request body:", body);
    
    try {
      const ipAddress: string = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
      const userAgent: string = request.headers.get('user-agent') || 'unknown';
      
      console.log("🔍 IP Address:", ipAddress);
      console.log("🔍 User Agent:", userAgent);
      
      const { email } = body as { email: string };
      console.log("🔍 Extracted email:", email);
      
      if (!email) {
        console.log("🔍 Email validation failed - email is empty");
        await logFailedAuthActivity('password_reset_request_failed', email || 'unknown', 'Email is required', ipAddress, userAgent);
        set.status = 400;
        return { error: "Email-ul este obligatoriu" };
      }

      console.log("🔍 Checking if user exists for email:", email);
      // Check if user exists (classic or OAuth)
      const userResult = await PasswordResetService.findUserByEmail(email);
      console.log("🔍 User result:", userResult);
      
      if (!userResult.exists) {
        // Don't reveal if user exists or not for security
        await logFailedAuthActivity('password_reset_request_failed', email, 'User not found', ipAddress, userAgent);
        return { message: "Dacă acest email există în sistemul nostru, vei primi instrucțiuni de resetare." };
      }

      // Create reset token
      console.log("🔍 Creating reset token for user type:", userResult.type);
      const resetToken = await PasswordResetService.createResetToken(email, userResult.type);
      console.log("🔍 Reset token created successfully");
      
      // Send reset email
      console.log("🔍 Sending password reset email to:", email);
      await EmailService.sendPasswordResetEmail(email, resetToken);
      console.log("🔍 Password reset email sent successfully");
      
      // Log successful request
      await logAuthActivity('password_reset_requested', email, {
        user_type: userResult.type
      }, ipAddress, userAgent);

      console.log("🔍 === PASSWORD RESET REQUEST SUCCESS ===");
      return { 
        message: "Dacă acest email există în sistemul nostru, vei primi instrucțiuni de resetare.",
        token: resetToken // Include token in response for development
      };
      
    } catch (error) {
      console.error("🔍 === PASSWORD RESET REQUEST ERROR ===");
      console.error('Password reset request error:', error);
      console.error('Error type:', typeof error);
      console.error('Error message:', error instanceof Error ? error.message : 'Unknown error');
      console.error('Error stack:', error instanceof Error ? error.stack : 'No stack trace');
      
      const requestBody = body as { email: string };
      const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
      const userAgent = request.headers.get('user-agent') || 'unknown';
      
      await logFailedAuthActivity('password_reset_request_failed', requestBody.email || 'unknown', 'Internal server error', ipAddress, userAgent);
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  })

  .post("/reset-password", async ({ body, request, set }) => {
    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    try {
      const { token, newPassword } = body as { token: string; newPassword: string };
      
      if (!token || !newPassword) {
        await logFailedAuthActivity('password_reset_failed', 'unknown', 'Token and password are required', ipAddress, userAgent);
        set.status = 400;
        return { error: "Token-ul și parola nouă sunt obligatorii" };
      }

      if (newPassword.length < 6) {
        await logFailedAuthActivity('password_reset_failed', 'unknown', 'Password too short', ipAddress, userAgent);
        set.status = 400;
        return { error: "Parola trebuie să aibă cel puțin 6 caractere" };
      }

      // Validate token
      const tokenData = await PasswordResetService.validateResetToken(token);
      
      if (!tokenData) {
        await logFailedAuthActivity('password_reset_failed', 'unknown', 'Invalid or expired token', ipAddress, userAgent);
        set.status = 400;
        return { error: "Token invalid sau expirat" };
      }

      // Reset password based on user type
      if (tokenData.userType === 'classic') {
        await PasswordResetService.resetClassicUserPassword(tokenData.email, newPassword);
      } else {
        await PasswordResetService.resetOAuthUserPassword(tokenData.email, newPassword);
      }

      // Mark token as used
      await PasswordResetService.markTokenAsUsed(token);
      
      // Send confirmation email
      await EmailService.sendPasswordResetConfirmationEmail(tokenData.email);
      
      // Log successful password reset
      await logAuthActivity('password_reset_completed', tokenData.email, {
        user_type: tokenData.userType
      }, ipAddress, userAgent);

      return { message: "Parola a fost resetată cu succes" };
      
    } catch (error) {
      console.error('Password reset error:', error);
      await logFailedAuthActivity('password_reset_failed', 'unknown', 'Internal server error', ipAddress, userAgent);
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  })

  .all("/request-password-reset", ({ request, set }) => {
    console.log("🔍 === ALL REQUEST TO /request-password-reset ===");
    console.log("🔍 Method:", request.method);
    console.log("🔍 URL:", request.url);
    console.log("🔍 Headers:", Object.fromEntries(request.headers.entries()));
    
    if (request.method === "OPTIONS") {
      set.status = 200;
      return { message: "CORS preflight OK" };
    }
    
    set.status = 405;
    return { error: "Method not allowed" };
  });
