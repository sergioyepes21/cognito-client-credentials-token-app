import { Body, Controller, Get, Post } from '@nestjs/common';
import { Public } from './decorators/public.decorators';
import { AuthDto } from './dtos/auth.dto';
import * as jwt from 'jsonwebtoken';
import { PrivateClientCredential } from './decorators/private-client-credential.decorators';
import { ConfigService } from '@nestjs/config';

@Controller()
export class AppController {

  /**
   * Auth JWT secret loaded by env variables
   */
  private AUTH_JWT_SECRET = '';

  /**
   * Class constructor
   * @param configService Project config service
   */
  constructor(
    private configService: ConfigService,
  ) {
    this.AUTH_JWT_SECRET = this.configService.get<string>('AUTH_JWT_SECRET');
  }

  /**
   * Public token generation endpoint
   * @param authDto User authentication info
   * @returns User authentication info with the generated access_token
   */
  @Public()
  @Post('/token')
  generateToken(
    @Body() authDto: AuthDto
  ): AuthDto {
    const { email, name, username: sub } = authDto;
    authDto.access_token = jwt.sign({ sub, email, name }, this.AUTH_JWT_SECRET);
    return authDto;
  }

  /**
   * Hello message protected by basic JWT authorization
   * @returns string
   */
  @Get('/jwt-secret/hello')
  getJwtTokenHello(): string {
    return 'jwt secret hello';
  }

  /**
   * Hello message protected by Cognito client-credentials grant type
   * @returns string
   */
  @PrivateClientCredential()
  @Get('/client-credentials/hello')
  getPrivateClientCredentialsHello(): string {
    return 'client-credentials hello';
  }
}
