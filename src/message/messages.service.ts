import {
    Injectable,
    NotFoundException,
    BadRequestException,
} from '@nestjs/common'
import { PrismaService } from '../prisma/prisma.service';
import {
    CreateContactMessageDto,
    ListContactMessagesDto,
    UpdateMessageStatusDto,
    ReplyToContactMessageDto,
} from './dto/index';
import { MessageStatus } from '@prisma/client'

@Injectable()
export class MessagesService {
    constructor(private readonly prisma: PrismaService) { }


    async create(dto: CreateContactMessageDto) {
        return this.prisma.contactMessage.create({
            data: {
                name: dto.name,
                email: dto.email,
                phone: dto.phone,
                subject: dto.subject,
                message: dto.message,
            },
        })
    }

    async findAll(filters: ListContactMessagesDto) {
        const { status, search } = filters

        return this.prisma.contactMessage.findMany({
            where: {
                status: status ?? undefined,
                OR: search
                    ? [
                        { email: { contains: search, mode: 'insensitive' } },
                        { name: { contains: search, mode: 'insensitive' } },
                        { subject: { contains: search, mode: 'insensitive' } },
                        { message: { contains: search, mode: 'insensitive' } },
                    ]
                    : undefined,
            },
            orderBy: { createdAt: 'desc' },
            include: {
                lastRepliedBy: {
                    select: { id: true, email: true, displayName: true },
                },
            },
        })
    }

    async findOne(id: string) {
        const message = await this.prisma.contactMessage.findUnique({
            where: { id },
            include: {
                replies: {
                    orderBy: { createdAt: 'asc' },
                    include: {
                        author: {
                            select: { id: true, email: true, displayName: true },
                        },
                    },
                },
            },
        })

        if (!message) {
            throw new NotFoundException('Contact message not found')
        }

        return message
    }

    async updateStatus(id: string, dto: UpdateMessageStatusDto) {
        if (dto.status === MessageStatus.REPLIED) {
            throw new BadRequestException(
                'REPLIED status is only set via reply endpoint',
            )
        }

        const message = await this.prisma.contactMessage.findUnique({
            where: { id },
        })

        if (!message) {
            throw new NotFoundException('Contact message not found')
        }

        return this.prisma.contactMessage.update({
            where: { id },
            data: {
                status: dto.status,
                readAt:
                    dto.status === MessageStatus.READ && !message.readAt
                        ? new Date()
                        : message.readAt,
            },
        })
    }

    async markAsRead(id: string) {
        const message = await this.prisma.contactMessage.findUnique({
            where: { id },
        })

        if (!message) {
            throw new NotFoundException('Contact message not found')
        }

        if (message.status !== MessageStatus.NEW) {
            return message
        }

        return this.prisma.contactMessage.update({
            where: { id },
            data: {
                status: MessageStatus.READ,
                readAt: new Date(),
            },
        })
    }

    async replyToMessage(
        messageId: string,
        adminUserId: string,
        dto: ReplyToContactMessageDto,
    ) {
        return this.prisma.$transaction(async (tx) => {
            const message = await tx.contactMessage.findUnique({
                where: { id: messageId },
            })

            if (!message) {
                throw new NotFoundException('Contact message not found')
            }

            const reply = await tx.contactMessageReply.create({
                data: {
                    contactMessageId: messageId,
                    authorId: adminUserId,
                    content: dto.content,
                    sentVia: 'EMAIL',
                },
            })

            await tx.contactMessage.update({
                where: { id: messageId },
                data: {
                    status: MessageStatus.REPLIED,
                    repliedAt: new Date(),
                    lastRepliedById: adminUserId,
                },
            })

            return reply
        })
    }
}
