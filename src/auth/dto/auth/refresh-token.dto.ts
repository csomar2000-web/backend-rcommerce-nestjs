import { IsString, Length } from 'class-validator';

export class RefreshTokenDto {
  @IsString()
  @Length(32, 512)
  refreshToken: string;
}
