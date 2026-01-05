import {
  IsEmail,
  IsString,
  MinLength,
  IsPhoneNumber,
} from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  @MinLength(8)
  confirmPassword: string;

  @IsPhoneNumber(undefined)
  phoneNumber: string;
}
