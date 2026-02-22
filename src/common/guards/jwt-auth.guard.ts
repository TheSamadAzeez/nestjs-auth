// src/auth/guards/jwt-auth.guard.ts
import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Check if the route is marked @Public() — if so, skip auth entirely
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(), // Check the handler i.e inline @Public() decorator takes precedence
      context.getClass(), // Check the class i.e @Public() decorator on the controller second
    ]);
    if (isPublic) return true;
    return super.canActivate(context); //Pass control to the parent class canActivate method so it can do its job

    // or you can do it like this
    //    import {
    //      CanActivate,
    //      ExecutionContext,
    //      Injectable,
    //      UnauthorizedException,
    //    } from '@nestjs/common';
    //    import { Reflector } from '@nestjs/core';
    //    import { IS_PUBLIC } from '../decorators/public.decorator';
    //    import { TokenService } from '../services/token.service';

    //    @Injectable()
    //    export class JwtAuthGuard implements CanActivate {
    //      constructor(
    //        private reflector: Reflector,
    //        private tokenService: TokenService,
    //      ) {}

    //      canActivate(context: ExecutionContext): boolean {
    //        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
    //          context.getHandler(),
    //          context.getClass(),
    //        ]);
    //        if (isPublic) return true;

    //        const request = context.switchToHttp().getRequest();
    //        const authHeader = request.headers.authorization;

    //        if (!authHeader?.startsWith('Bearer ')) {
    //          throw new UnauthorizedException({
    //            code: 'MISSING_TOKEN',
    //            message: 'Authentication required',
    //          });
    //        }

    //        try {
    //          const token = authHeader.slice(7);
    //          request.user = this.tokenService.verifyAccessToken(token);
    //          return true;
    //        } catch {
    //          throw new UnauthorizedException({
    //            code: 'INVALID_TOKEN',
    //            message: 'Invalid or expired token',
    //          });
    //        }
    //      }
    //    }
  }
}
