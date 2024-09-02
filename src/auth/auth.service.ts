import { ForbiddenException, Injectable } from '@nestjs/common';
import { SignupInput } from './dto/signup.input';
import { UpdateAuthInput } from './dto/update-auth.input';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon from 'argon2';
import { SigninInput } from './dto/signin.input';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  async signup(signupInput: SignupInput) {
    const exists = await this.prismaService.user.findUnique({
      where: { email: signupInput.email },
    });
    if (exists) {
      throw new Error('User already exists');
    }
    const hashedPassword = await argon.hash(signupInput.password);
    const user = await this.prismaService.user.create({
      data: {
        email: signupInput.email,
        password: hashedPassword,
        name: signupInput.name,
      },
    });
    const { accessToken, refreshToken } = await this.createToken(
      user.id,
      user.email,
    );
    await this.updateRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken, user };
  }

  async signin(signinInput: SigninInput) {
    const user = await this.prismaService.user.findUnique({
      where: { email: signinInput.email },
    });
    if (!user) {
      throw new ForbiddenException('Access Denied');
    }
    const isPasswordCorrect = await argon.verify(
      user.password,
      signinInput.password,
    );
    if (!isPasswordCorrect) {
      throw new ForbiddenException('Access Denied');
    }
    const { accessToken, refreshToken } = await this.createToken(
      user.id,
      user.email,
    );
    await this.updateRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken, user };
  }

  async logout(userId: number) {
    const user = await this.prismaService.user.findFirst({
      where: { id: userId, hashedRefreshToken: { not: null } },
    });
    if (!user) {
      throw new Error('User is already logged out');
    }
    await this.prismaService.user.update({
      where: { id: userId, hashedRefreshToken: { not: null } },
      data: { hashedRefreshToken: null },
    });
    return { loggedOut: true };
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthInput: UpdateAuthInput) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
  async createToken(userId: number, email: string) {
    const accessToken = this.jwtService.sign(
      { userId, email },
      {
        expiresIn: '1h',
        secret: this.configService.get('ACCESS_TOKEN_SECRET'),
      },
    );
    const refreshToken = this.jwtService.sign(
      { userId, email, accessToken },
      {
        expiresIn: '1d',
        secret: this.configService.get('REFRESH_TOKEN_SECRET'),
      },
    );
    return { accessToken, refreshToken };
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await argon.hash(refreshToken);
    await this.prismaService.user.update({
      where: { id: userId },
      data: { hashedRefreshToken },
    });
  }

  async getNewTokens(userId: number, rt: string) {
    const user = await this.prismaService.user.findFirst({
      where: { id: userId },
    });
    if (!user) {
      throw new ForbiddenException('Access Denied');
    }
    const deRefreshTokensMatch = await argon.verify(
      user.hashedRefreshToken,
      rt,
    );
    if (!deRefreshTokensMatch) {
      throw new ForbiddenException('Access Denied');
    }
    const { accessToken, refreshToken } = await this.createToken(
      user.id,
      user.email,
    );
    await this.updateRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken, user };
  }
}
