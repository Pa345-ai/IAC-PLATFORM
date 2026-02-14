import { Injectable } from '@nestjs/common';

@Injectable()
export class CalendarService {
  async getEvents(userId: string) {
    // Mock events for MVP
    return [
      { id: '1', title: 'Work', start: '2026-01-01T09:00:00Z', end: '2026-01-01T17:00:00Z' },
    ];
  }

  async syncWithGoogle(userId: string) {
    return { status: 'synced', source: 'google' };
  }
}
