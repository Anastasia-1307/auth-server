import { PrismaClient } from '../generated/prisma';
import { createHash, randomBytes } from 'crypto';

const prisma = new PrismaClient();

export class PasswordResetService {
  // Generate secure reset token
  static generateResetToken(): string {
    return randomBytes(32).toString('hex');
  }

  // Create password reset token
  static async createResetToken(email: string, userType: 'classic' | 'oauth'): Promise<string> {
    // Delete any existing unused tokens for this email
    await prisma.password_reset_tokens.deleteMany({
      where: {
        email,
        used: false,
        expires_at: {
          gt: new Date()
        }
      }
    });

    // Generate new token
    const token = this.generateResetToken();
    console.log("🔍 Generated reset token:", token); // Add this line to log the token
    
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // Token expires in 1 hour

    // Save token to database
    await prisma.password_reset_tokens.create({
      data: {
        email,
        token,
        expires_at: expiresAt,
        user_type: userType
      }
    });

    return token;
  }

  // Validate reset token
  static async validateResetToken(token: string): Promise<{ email: string; userType: string } | null> {
    const resetToken = await prisma.password_reset_tokens.findFirst({
      where: {
        token,
        used: false,
        expires_at: {
          gt: new Date()
        }
      }
    });

    if (!resetToken) {
      return null;
    }

    return {
      email: resetToken.email,
      userType: resetToken.user_type
    };
  }

  // Mark token as used
  static async markTokenAsUsed(token: string): Promise<void> {
    await prisma.password_reset_tokens.update({
      where: { token },
      data: { used: true }
    });
  }

  // Reset password for classic user
  static async resetClassicUserPassword(email: string, newPassword: string): Promise<void> {
    const hashedPassword = await Bun.password.hash(newPassword);
    
    await prisma.users.update({
      where: { email },
      data: { 
        password_hash: hashedPassword,
        updated_at: new Date()
      }
    });
  }

  // Reset password for OAuth user
  static async resetOAuthUserPassword(email: string, newPassword: string): Promise<void> {
    const hashedPassword = await Bun.password.hash(newPassword);
    
    await prisma.oauth_users.update({
      where: { email },
      data: { 
        password_hash: hashedPassword,
        updated_at: new Date()
      }
    });
  }

  // Check if user exists (classic or OAuth)
  static async findUserByEmail(email: string): Promise<{ type: 'classic' | 'oauth'; exists: boolean }> {
    const classicUser = await prisma.users.findUnique({
      where: { email }
    });

    if (classicUser) {
      return { type: 'classic', exists: true };
    }

    const oauthUser = await prisma.oauth_users.findUnique({
      where: { email }
    });

    if (oauthUser) {
      return { type: 'oauth', exists: true };
    }

    return { type: 'classic', exists: false };
  }
}
