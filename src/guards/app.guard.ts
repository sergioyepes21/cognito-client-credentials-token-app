import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { firstValueFrom, Observable } from 'rxjs';
import { IS_PUBLIC_KEY } from '../decorators/public.decorators';
import { IS_PRIVATE_CLIENT_CREDENTIAL_KEY } from '../decorators/private-client-credential.decorators';
import * as jwt from 'jsonwebtoken';
import { promisify } from 'util';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
const jwkToPem = require('jwk-to-pem');

/**
 * Claim verify result with the client user info associated
 */
interface ClaimVerifyResult {
    readonly clientId: string;
    readonly isValid: boolean;
    readonly error?: any;
}

/**
 * Cognito token headers
 */
interface TokenHeader {
    kid: string;
    alg: string;
}

/**
 * Cognito public key info
 */
interface PublicKey {
    alg: string;
    e: string;
    kid: string;
    kty: string;
    n: string;
    use: string;
}

/**
 * Metadata about the Cognito public key
 */
interface PublicKeyMeta {
    instance: PublicKey;
    pem: string;
}

/**
 * Cognito Public key list
 */
interface PublicKeys {
    keys: PublicKey[];
}

/**
 * Mapped Cognito Public keys
 */
interface MapOfKidToPublicKey {
    [key: string]: PublicKeyMeta;
}

/**
 * The request claim for authorization
 */
interface Claim {
    token_use: string;
    auth_time: number;
    iss: string;
    exp: number;
    sub: string;
    client_id: string;
}


/**
 * ApiTokenGuard Route guard
 * Following the awslabs support project for decoding Cognito token https://github.com/awslabs/aws-support-tools/blob/9caf00baa61bff9f7c40c888a7882c2d9f6e98e2/Cognito/decode-verify-jwt/decode-verify-jwt.ts
 * @implements {CanActivate}
 */
@Injectable()
export class ApiTokenGuard implements CanActivate {

    /**
     * Auth JWT secret loaded by env variables
     */
    private AUTH_JWT_SECRET = '';

    /**
     * Cognito issuer
     */
    private COGNITO_ISSUER = 'https://cognito-idp.us-east-1.amazonaws.com/';

    /**
     * Cognito user pool keys cached
     */
    private cacheKeys: MapOfKidToPublicKey | undefined;

    /**
     * Class constructor
     * @param reflector Http Reflector
     * @param configService Project config service
     * @param httpService Http service
     */
    constructor(
        private readonly reflector: Reflector,
        private configService: ConfigService,
        private readonly httpService: HttpService,
    ) {
        this.AUTH_JWT_SECRET = this.configService.get<string>('AUTH_JWT_SECRET');
        this.COGNITO_ISSUER += this.configService.get<string>('COGNITO_POOL_ID');
    }

    /**
     * Implements the logic to authorize or not a request
     * @param context
     * @returns boolean | Promise<boolean> | Observable<boolean>
     */
    canActivate(
        context: ExecutionContext,
    ): boolean | Promise<boolean> | Observable<boolean> {
        const isPublic = this.reflector.get(IS_PUBLIC_KEY, context.getHandler());
        if (isPublic) return true;

        return new Promise(async (resolve, reject) => {
            try {
                const authorization = context.switchToHttp().getRequest().headers.authorization;
                if (!authorization) return resolve(false);

                let isAllowed = false;
                const isPrivateClientCredential = this.reflector.get(IS_PRIVATE_CLIENT_CREDENTIAL_KEY, context.getHandler());
                if (isPrivateClientCredential) {
                    const access_token = authorization.replace(/\bbasic\b\s/gi, '');
                    const claimVerifyResult = await this.validateCognitoClientCredential(access_token);
                    isAllowed = claimVerifyResult.isValid;
                } else {
                    const access_token = authorization.replace(/\bbearer\b\s/gi, '');
                    // If token is
                    await this.verifyPromised(access_token, this.AUTH_JWT_SECRET);
                    isAllowed = true;
                }
                return resolve(isAllowed);
            } catch (e) {
                console.log(e);
                return reject(false);
            }
        })
    }

    /**
     * Requests for the UserPool's public keys to Cognito
     * @returns MapOfKidToPublicKey
     */
    private async getCognitoPublicKeys(): Promise<MapOfKidToPublicKey> {
        if (!this.cacheKeys) {
            const url = `${this.COGNITO_ISSUER}/.well-known/jwks.json`;
            // Requesting for the Cognito public keys
            const publicKeys = (await firstValueFrom(this.httpService.get<PublicKeys>(url))).data;
            // Mapping the Cognito public keys
            this.cacheKeys = publicKeys.keys.reduce((agg, current) => {
                const pem = jwkToPem(current);
                agg[current.kid] = { instance: current, pem };
                return agg;
            }, {} as MapOfKidToPublicKey)
        }
        return this.cacheKeys;
    }

    /**
     * Transforming the jwt.verify method to a promise
     */
    private verifyPromised = promisify(jwt.verify.bind(jwt));

    /**
     * Validating Cognito client credentials
     * @param access_token Request access token
     * @returns ClaimVerifyResult
     */
    private async validateCognitoClientCredential(access_token: string): Promise<ClaimVerifyResult> {
        let result: ClaimVerifyResult;
        try {
            const tokenSections = (access_token || '').split('.');
            // Basic token form validation
            if (tokenSections.length < 2) {
                throw new Error('Requested token is invalid');
            }
            const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
            const header = JSON.parse(headerJSON) as TokenHeader;
            const keys = await this.getCognitoPublicKeys();
            const key = keys[header.kid];
            // Checking if the token's headers have been modified
            if (key === undefined) {
                throw new Error('Claim made for unknown kid');
            }
            // Validating token sign
            const claim = await this.verifyPromised(access_token, key.pem) as Claim;
            const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
            // Validating token's expiration
            if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
                throw new Error('Claim is expired or invalid');
            }
            if (claim.iss !== this.COGNITO_ISSUER) {
                throw new Error('Claim issuer is invalid');
            }
            if (claim.token_use !== 'access') {
                throw new Error('Claim use is not access');
            }
            result = { clientId: claim.client_id, isValid: true };
        } catch (error) {
            result = { clientId: '', error, isValid: false };
        }
        return result;
    }
}
