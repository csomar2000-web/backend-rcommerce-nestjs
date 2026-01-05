import { IsOptional, IsBoolean } from 'class-validator';

export class LogoutDto {
  @IsOptional()
  @IsBoolean()
  logoutAll?: boolean;
}
