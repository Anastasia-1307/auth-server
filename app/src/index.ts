import 'dotenv/config';
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
  .onRequest(({ request }) => {
  console.log(
    `🔍 ${request.method} ${request.url}`,
    Object.fromEntries(request.headers.entries())
  );
})
  .onBeforeHandle(({ request, set }) => {
    // Add JSON content type handling
    if (request.method && ['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const contentType = request.headers.get('content-type');
      if (contentType?.includes('application/json')) {
        // Elysia will automatically parse JSON bodies
        console.log('🔍 JSON request detected');
      }
    }
  })
  .onError(({ error, set, code }) => {
    console.error('🔍 Auth Server Error:', { error: error.message, code });
    if (code === 'PARSE') {
      set.status = 400;
      return { error: 'Invalid JSON body' };
    }
  })
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
