import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { TokensDto } from '../dto/auth.dto';
import { LoginDto } from '../dto/login.dto';
import { SignupDto } from '../dto/signup.dto';
import { JwtProvider } from '../jwt/jwt.provider';
import { Roles } from '../user/role.provider';
import { UserService } from '../user/user.service';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtProvider,
  ) {}

  async loginUser(user: LoginDto, shouldBeAdmin:boolean = false): Promise<TokensDto> {
    const dbUser = await this.userService.findOneByEmail({
      email: user.email,
    });

    if (!dbUser) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(
      user.password,
      dbUser.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    if (shouldBeAdmin && dbUser.role !== Roles.ADMIN) {
      throw new UnauthorizedException('Admin access required');
    }

    return await this.jwtService.generateAccessToken(dbUser);
  }

  async signupUser(user: SignupDto): Promise<TokensDto> {
    const dbUser = await this.userService.createUser(user);
    return await this.jwtService.generateAccessToken(dbUser);
  }

  async refreshToken(token: string): Promise<TokensDto> {
    const user = await this.jwtService.verifyToken(token);
    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const dbUser = await this.userService.findOneById(user.sub);
    if (!dbUser) {
      throw new UnauthorizedException('User not found');
    }

    return await this.jwtService.generateAccessToken(dbUser);
  }
}
