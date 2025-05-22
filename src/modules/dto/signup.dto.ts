import { IsEmail, IsNotEmpty, IsOptional } from 'class-validator';

export class SignupDto {
  @IsNotEmpty()
  readonly name: string;

  @IsEmail()
  readonly email: string;

  @IsNotEmpty()
  readonly password: string;
}
