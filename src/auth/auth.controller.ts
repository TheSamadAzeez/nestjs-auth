import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from 'src/common/decorators/public.decorator';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import type { JwtPayload } from 'src/common/types/jwt-payload.type';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dtos/create-user.dto';
import { LoginDto } from './dtos/login.dto';
import { TokenService } from './token.service';

const REFRESH_COOKIE = 'refresh_token';

// Secure cookie config — adjust sameSite based on your deployment
const cookieOptions = {
  httpOnly: true, // JS cannot read this cookie — blocks XSS token theft
  secure: true, // HTTPS only
  sameSite: 'strict' as const, // blocks CSRF for most cases
  path: '/auth/refresh', // cookie only sent to this path, not every request
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
  ) {}

  @Post('register')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() body: CreateUserDto) {
    return await this.authService.register(
      body.email,
      body.password,
      body.name,
    );
  }

  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, tokens } = await this.authService.login(
      body.email,
      body.password,
    );
    // Refresh token goes in an HttpOnly cookie — never in the response body
    res.cookie(REFRESH_COOKIE, tokens.refreshToken, cookieOptions);

    // Access token goes in the response body — the client stores it in memory
    return {
      accessToken: tokens.accessToken,
      user: { id: user.id, email: user.email, role: user.role },
      message: 'Login successful',
    };
  }

  @Post('refresh')
  @Public() //validated by cookies
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const rawToken = req.cookies[REFRESH_COOKIE] as string;
    if (!rawToken) {
      throw new UnauthorizedException({
        code: 'NO_REFRESH_TOKEN',
        message: 'No refresh token provided',
      });
    }
    const { tokens } = await this.authService.refresh(rawToken);
    // Issue new refresh token cookie (rotation)
    res.cookie(REFRESH_COOKIE, tokens.refreshToken, cookieOptions);

    return {
      accessToken: tokens.accessToken,
      message: 'Token refreshed successfully',
    };
  }

  @Post('logout')
  @HttpCode(200)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rawToken = req.cookies[REFRESH_COOKIE] as string;

    if (rawToken) {
      await this.authService.logout(rawToken);
    }

    res.clearCookie(REFRESH_COOKIE, { path: '/auth/refresh' });
    return {
      message: 'Logged out successfully',
    };
  }

  // "Logout everywhere" — revoke all sessions
  @Post('logout-all')
  @HttpCode(200)
  async logoutAll(
    @CurrentUser() user: JwtPayload,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.tokenService.revokeAllForUser(user.id);
    res.clearCookie(REFRESH_COOKIE, { path: '/auth/refresh' });
    return { message: 'All sessions terminated' };
  }
}
