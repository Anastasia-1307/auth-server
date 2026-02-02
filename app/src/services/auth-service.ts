import { prisma } from "../lib/prisma";
import { validateRegistration } from "../lib/validation";

export async function createUser(data: {
  email: string;
  username: string;
  password: string;
  role?: string;
}) {
  const errors = validateRegistration(data);
  if (errors.length > 0) {
    throw new Error(JSON.stringify(errors));
  }

  const existingUser = await prisma.users.findUnique({ 
    where: { email: data.email } 
  });
  
  if (existingUser) {
    throw new Error("Email deja folosit");
  }

  const passwordHash = await Bun.password.hash(data.password, { 
    algorithm: "argon2id" 
  });

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
