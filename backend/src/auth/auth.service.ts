import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  private generateTokens(username: string) {
    // TODO: Implement token generation
    const payload = { sub: username, username };

    const accessToken = this.jwtService.sign(payload);

    // Add a small nonce to refresh token payload so it rotates on each generation
    const refreshPayload = { ...payload, nonce: `${Date.now()}_${Math.random()}` };
    const refreshToken = this.jwtService.sign(refreshPayload, {
      secret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key-change-in-production',
      expiresIn: '7d', // Refresh token expires in 7 days
    });

    return { accessToken, refreshToken };
  }

  private async updateRefreshToken(username: string, refreshToken: string) {
    // TODO: Implement refresh token update
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    
    await this.prisma.user.update({
      where: { username },
      data: { refreshToken: hashedRefreshToken },
    });
  }

  async register(registerDto: RegisterDto) {
    // TODO: Implement user registration
    const { username, password } = registerDto;

    // Check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      throw new ConflictException('Username already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });

    // Generate tokens
    const tokens = this.generateTokens(user.username);

    // Update refresh token
    await this.updateRefreshToken(user.username, tokens.refreshToken);

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      user: { username: user.username },
    };
  }

  async login(loginDto: LoginDto) {
    // TODO: Implement user login
    const { username, password } = loginDto;

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const tokens = this.generateTokens(user.username);

    // Update refresh token
    await this.updateRefreshToken(user.username, tokens.refreshToken);

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      user: { username: user.username },
    };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto) {
     // TODO: Implement token refresh
    const { refreshToken } = refreshTokenDto;

    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key-change-in-production',
      });

      // Find user
      const user = await this.prisma.user.findUnique({
        where: { username: payload.username },
      });

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Verify stored refresh token
      const refreshTokenMatch = await bcrypt.compare(refreshToken, user.refreshToken);

      if (!refreshTokenMatch) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Generate new tokens
      const tokens = this.generateTokens(user.username);

      // Update refresh token
      await this.updateRefreshToken(user.username, tokens.refreshToken);

      return {
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(username: string) {
    // TODO: Implement user logout
    // Clear refresh token
    await this.prisma.user.update({
      where: { username },
      data: { refreshToken: null },
    });

    return { message: 'Logged out successfully' };
  }
}
