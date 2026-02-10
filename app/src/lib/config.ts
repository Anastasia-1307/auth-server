import dotenv from "dotenv";

dotenv.config();

export const config = {
  issuer: process.env.ISSUER || "http://localhost:4000",
  port: parseInt(process.env.PORT || "4000"),
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:3000",
  jwtAudience: process.env.JWT_AUDIENCE || "nextjs_client",
  codeExpiration: 5 * 60 * 1000, // 5 minutes
  tokenExpiration: "1h" as const,
  // Email configuration for MailHog
  email: {
    host: process.env.EMAIL_HOST || "localhost",
    port: parseInt(process.env.EMAIL_PORT || "1025"),
    secure: process.env.EMAIL_SECURE === "true",
    auth: {
      user: process.env.EMAIL_USER || "",
      pass: process.env.EMAIL_PASS || ""
    },
    from: process.env.EMAIL_FROM || "noreply@localhost"
  }
} as const;
