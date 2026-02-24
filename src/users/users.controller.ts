import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { Roles } from 'src/common/decorators/roles.decorator';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import type { JwtPayload } from 'src/common/types/jwt-payload.type';
import { Role } from 'src/common/enums/role.enum';
import { UsersService } from './users.service';
import { Public } from 'src/common/decorators/public.decorator';
import { EmailDto } from './dtos/email.dto';

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

  @Post()
  @Roles(Role.ADMIN)
  async getUserByEmail(@Body() body: EmailDto) {
    return await this.usersService.findUserByEmail(body.email);
  }

  @Get('all')
  @Roles(Role.ADMIN)
  async getAllUsers() {
    return await this.usersService.findAllUsers();
  }

  @Get(':userId')
  @Roles(Role.ADMIN)
  async getUserById(@Param('userId') userId: string) {
    return await this.usersService.findUserById(userId);
  }

  @Delete(':userId')
  @Roles(Role.ADMIN)
  async deleteUser(@Param('userId') userId: string) {
    const user = await this.usersService.deleteUser(userId);
    return {
      user,
      message: 'User deleted successfully',
    };
  }

  @Post('/deactivate/:userId')
  @Roles(Role.ADMIN)
  async deactivateUser(@Param('userId') userId: string) {
    const user = await this.usersService.deactivateUser(userId);
    return {
      user: { id: user.id, email: user.email, role: user.role },
      message: 'User deactivated successfully',
    };
  }

  @Get(':userId/profile')
  @Public()
  getPublicProfile(@Param('userId') userId: string) {
    return console.log(userId);
  }
}
