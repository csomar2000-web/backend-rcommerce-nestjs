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
import { AdminGuard } from '../auth/admin.guard';

@Controller('newsletter')
export class NewsletterController {
  constructor(private readonly newsletterService: NewsletterService) {}

  @Post('subscribe')
  subscribe(@Body() dto: SubscribeDto) {
    return this.newsletterService.subscribe(dto.email);
  }

  @Delete('unsubscribe')
  unsubscribe(@Body() dto: UnsubscribeDto) {
    return this.newsletterService.unsubscribe(dto.email);
  }

  @UseGuards(AdminGuard)
  @Get('admin/list')
  list(@Query() query: AdminListSubscribersDto) {
    const active =
      query.active === undefined ? undefined : query.active === 'true';

    return this.newsletterService.findAll(active);
  }

  @UseGuards(AdminGuard)
  @Get('admin/export')
  export(@Query() query: AdminListSubscribersDto) {
    const active =
      query.active === undefined ? undefined : query.active === 'true';

    return this.newsletterService.export(active);
  }
}
