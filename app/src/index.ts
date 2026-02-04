import { Elysia } from "elysia";
import { cookie } from "@elysiajs/cookie";
import { cors } from "@elysiajs/cors";
import { openapi } from "@elysiajs/openapi";
import { config } from "./lib/config";
import { authRoutes } from "./routes/auth-routes";
import { oauthRoutes } from "./routes/oauth-routes";
import { wellKnownRoutes } from "./routes/well-known-routes";
import { userRoutes } from "./routes/user-routes";
import { medicalRoutes } from "./routes/medical-routes";
import { adminRoutes } from "./routes/admin-routes";
import { patientRoutes } from "./routes/patient-routes";
import { dashboardRoutes } from "./routes/dashboard-routes";
import { errorHandler } from "./middleware/error-handler";
import { rateLimitPlugin } from "./middleware/rate-limiter";
import { prisma } from "./lib/prisma";

const app = new Elysia()
    .use(errorHandler)
    .use(rateLimitPlugin)
    .use(cookie())
    .use(cors({
      origin: config.corsOrigin,
      credentials: true,
      allowedHeaders: ['Content-Type', 'Authorization']
    }))
    .use(openapi())
    .use(authRoutes)
    .use(oauthRoutes)
    .use(wellKnownRoutes)
    .use(userRoutes)
    .use(medicalRoutes)
    .use(adminRoutes)
    .use(patientRoutes)
    .use(dashboardRoutes)

    .listen(config.port, ({ hostname, port }) => {
      console.log(`🚀 Auth Server rulează pe http://${hostname}:${port}`);
    });
