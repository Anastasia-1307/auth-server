import dotenv from "dotenv";

dotenv.config();

export const config = {
  issuer: process.env.ISSUER || "http://localhost:4000",
  port: parseInt(process.env.PORT || "4000"),
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:3000",
  jwtAudience: process.env.JWT_AUDIENCE || "nextjs_client",
  codeExpiration: 5 * 60 * 1000, // 5 minutes
  tokenExpiration: "1h" as const,
} as const;
