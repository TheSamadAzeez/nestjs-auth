import { Injectable, UnauthorizedException } from '@nestjs/common';
import { TokenService } from './token.service';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly tokenService: TokenService,
    private readonly usersService: UsersService,
  ) {}

  async register(email: string, password: string, name: string) {
    const user = await this.usersService.createUser(email, password, name);
    // await this.tokenService.issueTokens(user.id, user.email, user.role);
    return { user: { id: user.id, email: user.email, role: user.role } };
  }

  async login(email: string, password: string) {
    const user = await this.usersService.findUserByEmail(email);

    if (!user || !user.passwordHash) {
      throw new UnauthorizedException({
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid credentials',
      });
    }

    await this.usersService.validatePassword(password, user.passwordHash);

    const tokens = await this.tokenService.issueTokens(
      user.id,
      user.email,
      user.role,
    );
    return { user, tokens };
  }

  async refresh(refreshToken: string) {
    const { accessToken, refreshToken: newRefreshToken } =
      await this.tokenService.rotateRefreshToken(refreshToken);

    return {
      tokens: { accessToken, refreshToken: newRefreshToken },
    };
  }

  async logout(refreshToken: string) {
    await this.tokenService.invalidateToken(refreshToken);
  }
}
