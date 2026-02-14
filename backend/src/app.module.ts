import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { CalendarModule } from './calendar/calendar.module';
import { ActionsModule } from './actions/actions.module';
import { AiModule } from './ai/ai.module';
import { TrustModule } from './trust/trust.module';

@Module({
  imports: [
    AuthModule,
    UsersModule,
    CalendarModule,
    ActionsModule,
    AiModule,
    TrustModule,
  ],
})
export class AppModule {}
