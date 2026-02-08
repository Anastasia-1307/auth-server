import { prisma } from "../lib/prisma";
import { validateRegistration } from "../lib/validation";

export async function createOAuthUser(data: {
  email: string;
  username: string;
  password: string;
}) {
  const errors = validateRegistration(data);
  if (errors.length > 0) {
    throw new Error(JSON.stringify(errors));
  }

  const existingUser = await prisma.oauth_users.findUnique({ 
    where: { email: data.email } 
  });
  
  if (existingUser) {
    throw new Error("Email deja folosit");
  }

  const passwordHash = await Bun.password.hash(data.password, { 
    algorithm: "argon2id" 
  });

  return prisma.oauth_users.create({
    data: { 
      email: data.email, 
      username: data.username, 
      password_hash: passwordHash,
      role: "pacient"
    },
    select: {
      id: true,
      email: true,
      username: true,
      role: true
    }
  });
}

export async function authenticateOAuthUser(email: string, password: string) {
  console.log("🔍 authenticateOAuthUser - Căutare utilizator pentru email:", email);
  
  const user = await prisma.oauth_users.findUnique({
    where: { email },
    select: { 
      id: true, 
      username: true, 
      password_hash: true, 
      role: true 
    }
  });

  console.log("🔍 authenticateOAuthUser - Utilizator găsit:", !!user);
  if (user) {
    console.log("🔍 authenticateOAuthUser - User details:", {
      id: user.id,
      username: user.username,
      email: user.email || 'N/A',
      role: user.role
    });
  }

  if (!user) {
    console.log("❌ authenticateOAuthUser - Utilizatorul nu există în BD");
    throw new Error("Credentiale invalide");
  }

  console.log("🔍 authenticateOAuthUser - Verificare parolă...");
  const passwordMatch = await Bun.password.verify(password, user.password_hash);
  console.log("🔍 authenticateOAuthUser - Parolă validă:", passwordMatch);

  if (!passwordMatch) {
    console.log("❌ authenticateOAuthUser - Parolă incorectă");
    throw new Error("Credentiale invalide");
  }

  console.log("✅ authenticateOAuthUser - Autentificare reușită pentru:", user.username);
  return user;
}

export async function validateOAuthClient(clientId: string, redirectUri: string) {
  const client = await prisma.oauth_clients.findUnique({
    where: { client_id: clientId },
    select: { redirect_uris: true }
  });

  if (!client || !client.redirect_uris.includes(redirectUri)) {
    throw new Error("Unsupported redirect_uri");
  }

  return client;
}
