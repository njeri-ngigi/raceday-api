import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TokensDto } from '../dto/auth.dto';
import { User } from '../user/user.model';

export type UserJWTPayload = Pick<User, 'email' | 'id' | 'role'>;

type RefreshTokenPayload = {
  sub: string; // user ID
}

@Injectable()
export class JwtProvider {
  constructor(private jwtService: JwtService) {}

  async getUserJWTPayloadFromToken(
    authHeader: string,
  ): Promise<UserJWTPayload> {
    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('Auth token not found');
    }

    const payload = await this.jwtService.decode(token);
    if (!payload) {
      throw new UnauthorizedException('Invalid token');
    }

    return payload;
  }

  async generateAccessToken(user: UserJWTPayload): Promise<TokensDto> {
    const payload = { email: user.email, id: user.id, role: user.role };
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '1h' });
    const refreshToken = await this.jwtService.signAsync({sub: user.id}, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }

  async verifyToken(token: string): Promise<RefreshTokenPayload> {
    try {
      return this.jwtService.verify<RefreshTokenPayload>(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
