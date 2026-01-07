import { IsString, IsNotEmpty } from 'class-validator';

export class FacebookAuthDto {
  @IsString()
  @IsNotEmpty()
  accessToken: string;
}
