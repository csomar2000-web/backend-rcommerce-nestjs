import { IsString } from 'class-validator';
import { MatchFields } from '../../../common/validators/match-fields.validator';
import { StrongPassword } from '../common/password-rules';

export class ResetPasswordDto {
  @IsString()
  token: string;

  @IsString()
  @StrongPassword()
  newPassword: string;

  @IsString()
  @MatchFields('newPassword', {
    message: 'Passwords do not match',
  })
  confirmPassword: string;
}
