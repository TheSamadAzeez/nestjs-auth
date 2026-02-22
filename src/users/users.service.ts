import {
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from 'src/db/db.module';
import * as schema from 'src/db/schema';
import { User } from 'src/db/schema/users';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>;

  async findUserById(userId: string) {
    const [user] = await this.db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);

    if (!user) {
      throw new NotFoundException({
        code: 'USER_NOT_FOUND',
        message: 'User not found',
      });
    }
    return user;
  }

  async findUserByEmail(email: string) {
    const [user] = await this.db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, email))
      .limit(1);
    return user ?? null; // return null if user not found
  }

  async findAllUsers() {
    const users = await this.db.select().from(schema.users);
    return users;
  }

  async createUser(
    email: string,
    password: string,
    name: string,
  ): Promise<User> {
    // check if user already exists
    const existingUser = await this.findUserByEmail(email);
    if (existingUser) {
      throw new ConflictException({
        code: 'ALREADY_EXISTS',
        message: 'User already exists',
      });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // create user
    const [user] = await this.db
      .insert(schema.users)
      .values({ email, passwordHash: hashedPassword, name })
      .returning();
    return user;
  }

  async deleteUser(userId: string) {
    const user = await this.findUserById(userId);
    await this.db.delete(schema.users).where(eq(schema.users.id, userId));
    return user;
  }

  async validatePassword(password: string, hash: string) {
    const valid = await bcrypt.compare(password, hash);
    if (!valid) {
      throw new UnauthorizedException({
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid credentials',
      });
    }
    return valid;
  }
}
