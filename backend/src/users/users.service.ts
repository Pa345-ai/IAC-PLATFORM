import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private readonly users = [
    {
      userId: '1',
      username: 'jules',
      // In production, this would be a hash from the database
      passwordHash: '$2b$10$EPfLwv.C1p.S.mU.yV9mX.Uv7V.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z',
    },
  ];

  async findOne(username: string): Promise<any | undefined> {
    const user = this.users.find(u => u.username === username);
    if (user) {
      // In production, use bcrypt.compare(password, user.passwordHash)
      return user;
    }
    return undefined;
  }
}
