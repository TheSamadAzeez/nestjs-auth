import { Controller, Delete, Get, Param, Patch } from '@nestjs/common';
import { Roles } from 'src/common/decorators/roles.decorator';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import type { JwtPayload } from 'src/common/types/jwt-payload.type';
import { Role } from 'src/common/enums/role.enum';
import { UsersService } from './users.service';
import { Public } from 'src/common/decorators/public.decorator';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  getUser(@CurrentUser() user: JwtPayload) {
    return user;
  }

  @Patch('me')
  updateUser() {
    return console.log('user updated');
  }

  @Get('all')
  @Roles(Role.ADMIN)
  getAllUsers() {
    return this.usersService.findAllUsers();
  }

  @Delete(':userId')
  @Roles(Role.ADMIN)
  deleteUser(@Param('userId') userId: string) {
    return this.usersService.deleteUser(userId);
  }

  @Get(':userId/profile')
  @Public()
  getPublicProfile(@Param('userId') userId: string) {
    return console.log(userId);
  }
}
