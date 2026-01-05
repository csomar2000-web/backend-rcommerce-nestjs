import { IsOptional, IsString } from 'class-validator';

export class AuthMetadataDto {
  @IsOptional()
  @IsString()
  deviceId?: string;

  @IsOptional()
  @IsString()
  deviceName?: string;
}
