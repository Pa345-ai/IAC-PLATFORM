import { Injectable } from '@nestjs/common';

@Injectable()
export class ActionsService {
  async executeAction(actionType: string, params: any) {
    switch (actionType) {
      case 'ORDER_FOOD':
        return this.orderFood(params);
      case 'BOOK_RIDE':
        return this.bookRide(params);
      case 'SEND_EMAIL':
        return this.sendEmail(params);
      default:
        return { status: 'error', detail: 'Unsupported action type' };
    }
  }

  private async orderFood(params: any) {
    return { status: 'success', detail: 'Food ordered via Uber Eats' };
  }

  private async bookRide(params: any) {
    return { status: 'success', detail: 'Ride booked via Uber' };
  }

  private async sendEmail(params: any) {
    return { status: 'success', detail: 'Email sent' };
  }
}
