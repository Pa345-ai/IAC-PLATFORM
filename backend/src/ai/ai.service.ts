import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class AiService {
  private readonly aiEngineUrl = process.env.AI_ENGINE_URL || 'http://localhost:8000';

  async getDecision(userContext: any, goalState: any, availableActions: string[]) {
    try {
      const response = await axios.post(`${this.aiEngineUrl}/decide`, {
        userContext,
        goalState,
        availableActions,
      });
      return response.data;
    } catch (error) {
      return { action: 'suggest_manual', reason: 'AI Engine unavailable' };
    }
  }

  async optimizeSchedule(events: any[]) {
    try {
      const response = await axios.post(`${this.aiEngineUrl}/optimize/schedule`, { events });
      return response.data;
    } catch (error) {
      return { status: 'error', detail: 'Could not optimize' };
    }
  }
}
