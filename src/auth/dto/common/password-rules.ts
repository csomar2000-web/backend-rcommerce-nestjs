import { Matches, MinLength } from 'class-validator';

export const PASSWORD_REGEX =
  /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/;

export function StrongPassword() {
  return function (target: any, propertyKey: string) {
    MinLength(12)(target, propertyKey);
    Matches(PASSWORD_REGEX, {
      message:
        'Password must be at least 12 characters and include upper, lower, number, and special character',
    })(target, propertyKey);
  };
}
