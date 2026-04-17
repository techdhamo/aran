import { UserRole } from '../enums/user-role.enum';

export interface UserSession {
  email: string;
  token: string;
  role: UserRole;
}
