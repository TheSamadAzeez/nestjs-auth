// src/common/guards/roles.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';
import { Request } from 'express';
import { JwtPayload } from '../types/jwt-payload.type';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Get the roles required for this route
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(), // method-level decorator takes priority
      context.getClass(), // falls back to class-level decorator
    ]);

    // If no @Roles() decorator, the route is accessible to any authenticated user
    if (!requiredRoles || requiredRoles.length === 0) return true;

    const { user } = context
      .switchToHttp()
      .getRequest<Request & { user: JwtPayload }>(); // appends the user property to the request object

    if (!user) throw new ForbiddenException('No user on request');

    const hasRole = requiredRoles.some((role) => user.role === role); // Check if the user has any of the required roles

    if (!hasRole) {
      throw new ForbiddenException({
        code: 'INSUFFICIENT_PERMISSIONS',
        message: `This action requires one of the following roles: ${requiredRoles.join(', ')}`,
      });
    }

    return true;
  }
}
