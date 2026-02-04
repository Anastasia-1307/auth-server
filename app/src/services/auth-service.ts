import { prisma } from "../lib/prisma";
import { validateRegistration } from "../lib/validation";

export async function createUser(data: {
  email: string;
  username: string;
  password: string;
  role?: string;
}) {
  console.log("🔍 createUser - Input data:", { email: data.email, username: data.username });
  
  const errors = validateRegistration(data);
  if (errors.length > 0) {
    console.log("❌ createUser - Validation errors:", errors);
    throw new Error(JSON.stringify(errors));
  }

  console.log("🔍 createUser - Checking existing user for email:", data.email);
  const existingUser = await prisma.users.findUnique({ 
    where: { email: data.email } 
  });
  
  if (existingUser) {
    console.log("❌ createUser - Email already exists:", data.email);
    throw new Error("Email deja folosit");
  }

  console.log("🔍 createUser - Hashing password...");
  const passwordHash = await Bun.password.hash(data.password, { 
    algorithm: "argon2id" 
  });

  console.log("🔍 createUser - Creating user in database...");
  return prisma.users.create({
    data: { 
      email: data.email, 
      username: data.username, 
      password_hash: passwordHash,
      role: data.role || "pacient"
    },
    select: { 
      id: true, 
      email: true, 
      username: true, 
      role: true 
    }
  });
}

export async function authenticateUser(email: string, password: string) {
  const user = await prisma.users.findUnique({
    where: { email },
    select: { 
      id: true, 
      email: true, 
      username: true, 
      password_hash: true, 
      role: true 
    }
  });

  if (!user || !(await Bun.password.verify(password, user.password_hash))) {
    throw new Error("Credentiale invalide");
  }

  return user;
}
