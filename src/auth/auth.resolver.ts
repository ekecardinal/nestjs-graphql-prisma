import { Resolver, Query, Mutation, Args, Int } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { Auth } from './entities/auth.entity';
import { SignupInput } from './dto/signup.input';
import { UpdateAuthInput } from './dto/update-auth.input';
import { sign } from 'crypto';
import { SignResponse } from './dto/sign-response';
import { SigninInput } from './dto/signin.input';
import { LogoutResponse } from './dto/logout-response';
import { Public } from './decorators/public.decorator';
import { UseGuards } from '@nestjs/common';
import { AcccessTokenGuard } from './guards/accessToken.guard';
import { CurrentUser } from './decorators/currentUser.decorator';
import { CurrentUserId } from './decorators/currentUserId.decorator';
import { RefreshTokenGuard } from './guards/refreshToken.guard';

@Resolver(() => Auth)
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Mutation(() => SignResponse)
  signup(@Args('signupInput') signupInput: SignupInput) {
    return this.authService.signup(signupInput);
  }

  @Public()
  @Mutation(() => SignResponse)
  signin(@Args('signinInput') signinInput: SigninInput) {
    return this.authService.signin(signinInput);
  }

  @Query(() => Auth, { name: 'auth' })
  findOne(@Args('id', { type: () => Int }) id: number) {
    return this.authService.findOne(id);
  }

  @Mutation(() => Auth)
  updateAuth(@Args('updateAuthInput') updateAuthInput: UpdateAuthInput) {
    return this.authService.update(updateAuthInput.id, updateAuthInput);
  }

  @Public()
  @Mutation(() => LogoutResponse)
  logout(@Args('id', { type: () => Int }) id: number) {
    return this.authService.logout(id);
  }

  // @UseGuards(AcccessTokenGuard)
  @Query(() => String)
  findings(@CurrentUserId() userId: number) {
    return `find all ${userId}`;
  }

  // @Public()
  @Query(() => String)
  hello() {
    return 'Hello World';
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Mutation(() => SignResponse)
  getNewTokens(
    @CurrentUserId() userId: number,
    @CurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.getNewTokens(userId, refreshToken);
  }
}
