import {
  Controller,
  Post,
  Body,
  Delete,
  Get,
  Query,
  UseGuards,
} from '@nestjs/common';
import { NewsletterService } from './newsletter.service';

import { SubscribeDto } from './dto/subscribe.dto';
import { UnsubscribeDto } from './dto/unsubscribe.dto';
import { AdminListSubscribersDto } from './dto/admin-list-subscribers.dto';

import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';

@Controller('newsletter')
export class NewsletterController {
  constructor(private readonly newsletterService: NewsletterService) { }

  /* ------------------------------ Public ---------------------------------- */

  @Post('subscribe')
  subscribe(@Body() dto: SubscribeDto) {
    return this.newsletterService.subscribe(dto.email);
  }

  @Delete('unsubscribe')
  unsubscribe(@Body() dto: UnsubscribeDto) {
    return this.newsletterService.unsubscribe(dto.email);
  }

  /* ------------------------------ Admin ----------------------------------- */

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Get('admin/list')
  list(@Query() query: AdminListSubscribersDto) {
    const active =
      query.active === undefined ? undefined : query.active === 'true';

    return this.newsletterService.findAll(active);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Get('admin/export')
  export(@Query() query: AdminListSubscribersDto) {
    const active =
      query.active === undefined ? undefined : query.active === 'true';

    return this.newsletterService.export(active);
  }
}
