import { SetMetadata } from '@nestjs/common';

/**
 * Holds the private client redential key
 */
export const IS_PRIVATE_CLIENT_CREDENTIAL_KEY = 'isPrivateClientCredential';

/**
 * Decorator to set a method as public and exclude it from the route guard
 */
export const PrivateClientCredential = () => SetMetadata(IS_PRIVATE_CLIENT_CREDENTIAL_KEY, true);