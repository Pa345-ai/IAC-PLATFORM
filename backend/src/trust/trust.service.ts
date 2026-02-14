import { Injectable } from '@nestjs/common';

@Injectable()
export class TrustService {
  private userTrustLevels: Map<string, string> = new Map();

  async getTrustLevel(userId: string) {
    return this.userTrustLevels.get(userId) || 'ASK';
  }

  async updateTrustLevel(userId: string, newLevel: string) {
    this.userTrustLevels.set(userId, newLevel);
    return { status: 'success', userId, newLevel };
  }
}
