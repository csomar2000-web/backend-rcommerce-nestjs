import { IsString, Length } from 'class-validator';

export class RefreshTokenDto {
  @IsString()
  @Length(32, 512, {
    message: 'Invalid refresh token format',
  })
  refreshToken: string;
}
