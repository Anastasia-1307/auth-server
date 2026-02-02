import { Elysia, t } from "elysia";
import { createUser, authenticateUser } from "../services/auth-service";
import { signAccessToken } from "../lib/jwt-service";
import { config } from "../lib/config";

export const authRoutes = new Elysia({ prefix: "/auth" })
  .post("/register", async ({ body, set }) => {
    try {
      const { email, username, password } = body as any;
      
      const user = await createUser({ email, username, password });
      const userRole = user.role ?? "pacient";
      
      // Generează token automat la înregistrare
      const accessToken = await signAccessToken({
        email: user.email,
        name: user.username,
        role: userRole,
        sub: user.id.toString()
      });
      
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
      if (error instanceof Error) {
        try {
          const errors = JSON.parse(error.message);
          set.status = 400;
          return { error: errors };
        } catch {
          if (error.message === "Email deja folosit") {
            set.status = 409;
            return { error: error.message };
          }
        }
      }
      
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  })

  .post("/login", async ({ body, set }) => {
    try {
      const { email, password } = body as { email: string; password: string };

      if (!email || !password) {
        set.status = 400;
        return { error: "Trebuie completate toate câmpurile" };
      }

      const user = await authenticateUser(email, password);
      const userRole = user.role ?? "pacient";

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
      if (error instanceof Error && error.message === "Credentiale invalide") {
        set.status = 401;
        return { error: error.message };
      }
      
      set.status = 500;
      return { error: "Eroare internă de server" };
    }
  });
