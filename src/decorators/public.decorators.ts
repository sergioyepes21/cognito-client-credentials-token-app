import { SetMetadata } from '@nestjs/common';

/**
 * Holds the public key value
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Decorator to set a method as public and exclude it from the route guard
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);