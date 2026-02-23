import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from 'src/common/types/jwt-payload.type';
import * as crypto from 'crypto';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from 'src/db/db.module';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from 'src/db/schema';

@Injectable()
export class TokenService {
  @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>;
  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {}

  // ─── Access Token ────────────────────────────────────────────────────────────
  // Short-lived, stateless. Only needs the secret to verify.
  async generateAccessToken(
    userId: string,
    email: string,
    role: string,
  ): Promise<string> {
    return await this.jwtService.signAsync(
      { id: userId, email, role },
      {
        secret: this.config.get('JWT_ACCESS_SECRET'),
        expiresIn: this.config.get('JWT_EXPIRES_IN'),
      },
    );
  }

  verifyAccessToken(token: string) {
    return this.jwtService.verify<JwtPayload>(token, {
      secret: this.config.get<string>('JWT_ACCESS_SECRET'),
    });
  }

  // ─── Refresh Token ───────────────────────────────────────────────────────────
  // Long-lived, stateful. We store a hash in the DB so we can revoke it.
  async generateRefreshToken(userId: string, family?: string): Promise<string> {
    // Cryptographically random — not a JWT. JWTs for refresh tokens leak expiry
    // info and are harder to rotate safely. A random opaque token is simpler.
    const rawToken = crypto.randomBytes(64).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');
    const tokenFamily = family ?? crypto.randomUUID(); // if no family provided, create a new one

    await this.db.insert(schema.refreshTokens).values({
      userId,
      tokenHash,
      familyId: tokenFamily,
      expiresAt: new Date(
        Date.now() +
          this.config.get('JWT_REFRESH_EXPIRES_IN', '7d') * 24 * 60 * 60 * 1000,
      ), // 7 days
    });

    return rawToken; // send raw to client; store only the hash
  }

  async validateRefreshToken(rawToken: string) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const [token] = await this.db
      .select()
      .from(schema.refreshTokens)
      .where(eq(schema.refreshTokens.tokenHash, tokenHash));

    if (!token) {
      throw new UnauthorizedException({
        code: 'INVALID_REFRESH_TOKEN',
        message: 'Invalid refresh token',
      });
    }

    if (token.used) {
      await this.invalidateFamily(token.familyId);

      throw new UnauthorizedException({
        code: 'REFRESH_TOKEN_REUSE',
        message: 'Refresh token reuse detected. Please log in again.',
      });
    }

    if (token.expiresAt < new Date()) {
      throw new UnauthorizedException({
        code: 'REFRESH_TOKEN_EXPIRED',
        message: 'Refresh token expired. Please log in again.',
      });
    }

    return token;
  }

  async issueTokens(
    userId: string,
    email: string,
    role: string,
    family?: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    // generate both tokens in parallel
    const [accessToken, refreshToken] = await Promise.all([
      this.generateAccessToken(userId, email, role),
      this.generateRefreshToken(userId, family),
    ]);
    return { accessToken, refreshToken };
  }

  async rotateRefreshToken(rawToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
    userId: string;
  }> {
    const token = await this.validateRefreshToken(rawToken);

    // Mark old token as used (don't delete — keeps audit trail and enables reuse detection)
    await this.db
      .update(schema.refreshTokens)
      .set({ used: true })
      .where(eq(schema.refreshTokens.id, token.id));

    // Fetch user for new token claims
    const [user] = await this.db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, token.userId));

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      await this.issueTokens(user.id, user.email, user.role, token.familyId);

    // const newAccessToken = await this.generateAccessToken(
    //   user.id,
    //   user.email,
    //   user.role,
    // );
    // const newRefreshToken = await this.generateRefreshToken(
    //   user.id,
    //   token.familyId,
    // ); // same family

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      userId: user.id,
    };
  }

  async invalidateFamily(family: string) {
    await this.db
      .update(schema.refreshTokens)
      .set({ used: true })
      .where(eq(schema.refreshTokens.familyId, family));
  }

  async invalidateToken(rawToken: string) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const [token] = await this.db
      .select()
      .from(schema.refreshTokens)
      .where(eq(schema.refreshTokens.tokenHash, tokenHash));

    if (!token) return;

    if (token.used || token.expiresAt < new Date()) return;

    await this.invalidateFamily(token.familyId);
  }

  async revokeAllForUser(userId: string) {
    await this.db
      .update(schema.refreshTokens)
      .set({ used: true })
      .where(eq(schema.refreshTokens.userId, userId));
  }
}
