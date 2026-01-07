import {
  IsEmail,
  IsString,
  MinLength,
  Matches,
  IsPhoneNumber,
} from 'class-validator';
import { MatchFields } from '../../../common/validators/match-fields.validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(12)
  @Matches(/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])/, {
    message:
      'Password must include upper, lower, number, and special character',
  })
  password: string;

  @IsString()
  @MatchFields('password', {
    message: 'Passwords do not match',
  })
  confirmPassword: string;

  @IsPhoneNumber(undefined)
  phoneNumber: string;
}
