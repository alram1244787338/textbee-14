import { HttpException, HttpStatus } from '@nestjs/common'

/**
 * Canonical error codes returned across the permission chain.
 *
 * Consumers (web dashboard, mobile app, integrations) can branch on the
 * machine-readable `code` field rather than parsing human-readable messages.
 */
export enum ErrorCode {
  UNAUTHENTICATED = 'UNAUTHENTICATED',
  FORBIDDEN = 'FORBIDDEN',
  API_KEY_REVOKED = 'API_KEY_REVOKED',
  ACCOUNT_BANNED = 'ACCOUNT_BANNED',
  EMAIL_NOT_VERIFIED = 'EMAIL_NOT_VERIFIED',
  SUBSCRIPTION_INACTIVE = 'SUBSCRIPTION_INACTIVE',
  DEVICE_NOT_FOUND = 'DEVICE_NOT_FOUND',
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
}

/**
 * Build a stable HttpException with both a human-readable `message` and a
 * machine-readable `code` so clients can differentiate error classes without
 * relying on string matching.
 */
export function makeHttpException(
  code: ErrorCode,
  message: string,
  status: HttpStatus,
  extra?: Record<string, unknown>,
): HttpException {
  return new HttpException(
    {
      error: message,
      code,
      ...extra,
    },
    status,
  )
}

// ── Convenience factories ────────────────────────────────────────────────

export function unauthenticatedException(
  message = 'Authentication required',
): HttpException {
  return makeHttpException(
    ErrorCode.UNAUTHENTICATED,
    message,
    HttpStatus.UNAUTHORIZED,
  )
}

export function forbiddenException(
  message = 'You do not have permission to access this resource',
): HttpException {
  return makeHttpException(
    ErrorCode.FORBIDDEN,
    message,
    HttpStatus.FORBIDDEN,
  )
}

export function apiKeyRevokedException(): HttpException {
  return makeHttpException(
    ErrorCode.API_KEY_REVOKED,
    'This API key has been revoked and can no longer be used',
    HttpStatus.UNAUTHORIZED,
  )
}

export function accountBannedException(): HttpException {
  return makeHttpException(
    ErrorCode.ACCOUNT_BANNED,
    'Your account has been suspended. Please contact support.',
    HttpStatus.FORBIDDEN,
  )
}

export function emailNotVerifiedException(): HttpException {
  return makeHttpException(
    ErrorCode.EMAIL_NOT_VERIFIED,
    'Please verify your email address to continue',
    HttpStatus.FORBIDDEN,
  )
}

export function subscriptionInactiveException(
  message = 'An active subscription is required for this operation',
): HttpException {
  return makeHttpException(
    ErrorCode.SUBSCRIPTION_INACTIVE,
    message,
    HttpStatus.PAYMENT_REQUIRED,
  )
}

export function deviceNotFoundException(): HttpException {
  return makeHttpException(
    ErrorCode.DEVICE_NOT_FOUND,
    'Device not found',
    HttpStatus.NOT_FOUND,
  )
}
