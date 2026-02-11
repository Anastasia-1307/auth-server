import { prisma } from '../lib/prisma';
import { generateRandomString } from '../lib/crypto-utils';

export interface RefreshTokenData {
  token_id: string;
  user_id: string;
  client_id: string;
  expires_at: Date;
}

export class RefreshTokenService {
  private static readonly TOKEN_LENGTH = 128;
  private static readonly EXPIRY_DAYS = 30; // 30 zile

  static async createRefreshToken(userId: string, clientId: string = 'web-client', isOAuthUser: boolean = false): Promise<string> {
    const tokenId = generateRandomString(this.TOKEN_LENGTH);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.EXPIRY_DAYS);

    // Check if user exists in appropriate table
    if (isOAuthUser) {
      const oauthUserExists = await prisma.oauth_users.findUnique({ where: { id: userId } });
      if (!oauthUserExists) {
        throw new Error(`Cannot create refresh token: OAuth user ${userId} does not exist`);
      }
    } else {
      const userExists = await prisma.users.findUnique({ where: { id: userId } });
      if (!userExists) {
        throw new Error(`Cannot create refresh token: user ${userId} does not exist`);
      }
    }

    await this.cleanupExpiredTokens(userId, isOAuthUser);

    const refreshToken = await prisma.refresh_tokens.create({
      data: {
        token_id: tokenId,
        user_id: isOAuthUser ? null : userId,
        oauth_user_id: isOAuthUser ? userId : null,
        client_id: clientId,
        expires_at: expiresAt,
      },
    });
    console.log('🔄 Refresh token created:', {
      tokenId: refreshToken.token_id,
      userId: refreshToken.user_id,
      expiresAt: refreshToken.expires_at,
    });

    return refreshToken.token_id;
  }

  static async validateRefreshToken(token: string): Promise<RefreshTokenData | null> {
    try {
      const refreshToken = await prisma.refresh_tokens.findUnique({
        where: { token_id: token },
        include: { users: true },
      });

      if (!refreshToken) {
        console.log('🔄 Refresh token not found:', token);
        return null;
      }

      if (refreshToken.expires_at < new Date()) {
        console.log('🔄 Refresh token expired:', token);
        await this.revokeRefreshToken(token);
        return null;
      }

      console.log('🔄 Refresh token validated:', {
        tokenId: refreshToken.token_id,
        userId: refreshToken.user_id,
        expiresAt: refreshToken.expires_at,
      });

      return {
        token_id: refreshToken.token_id,
        user_id: refreshToken.user_id!,
        client_id: refreshToken.client_id,
        expires_at: refreshToken.expires_at,
      };
    } catch (error) {
      console.error('🔄 Error validating refresh token:', error);
      return null;
    }
  }

  static async revokeRefreshToken(token: string): Promise<void> {
    try {
      await prisma.refresh_tokens.delete({
        where: { token_id: token },
      });
      console.log('🔄 Refresh token revoked:', token);
    } catch (error) {
      console.error('🔄 Error revoking refresh token:', error);
    }
  }

  static async revokeAllUserTokens(userId: string): Promise<void> {
    try {
      await prisma.refresh_tokens.deleteMany({
        where: { user_id: userId },
      });
      console.log('🔄 All refresh tokens revoked for user:', userId);
    } catch (error) {
      console.error('🔄 Error revoking all user refresh tokens:', error);
    }
  }

  static async rotateRefreshToken(oldToken: string): Promise<string | null> {
    const tokenData = await this.validateRefreshToken(oldToken);
    
    if (!tokenData) {
      return null;
    }

    // Revocă token-ul vechi
    await this.revokeRefreshToken(oldToken);

    // Creează token nou
    return await this.createRefreshToken(tokenData.user_id, tokenData.client_id);
  }

  private static async cleanupExpiredTokens(userId: string, isOAuthUser: boolean = false): Promise<void> {
    try {
      await prisma.refresh_tokens.deleteMany({
        where: {
          ...(isOAuthUser ? { oauth_user_id: userId } : { user_id: userId }),
          expires_at: { lt: new Date() },
        },
      });
    } catch (error) {
      console.error('🔄 Error cleaning up expired tokens:', error);
    }
  }

  static async cleanupAllExpiredTokens(): Promise<void> {
    try {
      const result = await prisma.refresh_tokens.deleteMany({
        where: {
          expires_at: { lt: new Date() },
        },
      });
      console.log('🔄 Cleaned up expired tokens:', result.count);
    } catch (error) {
      console.error('🔄 Error cleaning up all expired tokens:', error);
    }
  }
}
