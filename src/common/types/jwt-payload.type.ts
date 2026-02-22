import { Role } from '../enums/role.enum';

export interface JwtPayload {
  id: string;
  email: string;
  role: Role;
}
