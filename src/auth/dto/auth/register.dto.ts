import { IsEmail, IsString, IsPhoneNumber } from 'class-validator';
import { MatchFields } from '../../../common/validators/match-fields.validator';
import { StrongPassword } from '../common/password-rules';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @StrongPassword()
  password: string;

  @IsString()
  @MatchFields('password', {
    message: 'Passwords do not match',
  })
  confirmPassword: string;

  @IsPhoneNumber(undefined)
  phoneNumber: string;
}
