import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { Request, Response } from 'express';
import { PRODUCTION } from 'src/core/constants';
import { AuthDto } from '../dto/auth.dto';
import { LoginDto } from '../dto/login.dto';
import { SignupDto } from '../dto/signup.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  
  private refreshConfig = {
    httpOnly: true,
    secure: process.env.NODE_ENV === PRODUCTION,
    path: '/api/v1/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  }
  private REFRESH_TOKEN  = 'refreshToken';

  @Post('refresh')
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = req.cookies?.refreshToken;
    if (!token) {
      throw new UnauthorizedException('Refresh token is missing');
    }
    const { accessToken, refreshToken } = await 
      this.authService.refreshToken(token);
    res.cookie(this.REFRESH_TOKEN, refreshToken, this.refreshConfig);
    return { accessToken }
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() data: LoginDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<AuthDto> {
    const { accessToken, refreshToken } = await 
      this.authService.loginUser(data);
    res.cookie(this.REFRESH_TOKEN, refreshToken, this.refreshConfig);
    return { accessToken }
  }

  @HttpCode(HttpStatus.OK)
  @Post('admin/login')
  async loginAdmin(
    @Body() data: LoginDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<AuthDto > {
    const shouldBeAdmin = true;
    const { accessToken, refreshToken } = await 
      this.authService.loginUser(data, shouldBeAdmin);
    res.cookie(this.REFRESH_TOKEN, refreshToken, this.refreshConfig);
    return { accessToken }
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  async signup(
    @Body() data: SignupDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<AuthDto> {
    const { accessToken, refreshToken } = await 
      this.authService.signupUser(data);
    res.cookie(this.REFRESH_TOKEN, refreshToken, this.refreshConfig);
    return {accessToken}
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @Res({ passthrough: true }) res: Response
  ): Promise<void> {
    res.clearCookie(this.REFRESH_TOKEN, this.refreshConfig);
    res.status(HttpStatus.OK).send({ message: 'Logged out successfully' });
  }
}

// TODO: Log all requests to this controller
// TODO: Add logging and tracing