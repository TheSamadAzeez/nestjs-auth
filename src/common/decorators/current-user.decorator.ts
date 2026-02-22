import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

/**
 * Decorator that extracts the authenticated user from the request.
 * @param data - The property of the user to extract (e.g., 'id', 'email').
 * @param ctx - The execution context.
 * @returns The user object or the specified property of the user.
 */
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<Request>();

    // The JWT strategy's validate() attaches { id, email } to req.user
    return request.user as { id: string; email: string; role: string };
  },
);
