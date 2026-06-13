import {
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common'
import mongoose from 'mongoose'
import { UserRole } from '../../users/user-roles.enum'
import { AuthService } from '../auth.service'
import {
  forbiddenException,
  unauthenticatedException,
  makeHttpException,
  ErrorCode,
} from '../../common/error-codes'
import { HttpStatus } from '@nestjs/common'

@Injectable()
export class CanModifyApiKey implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    const apiKeyId = request.params.id
    const user = request.user

    // AuthGuard should have already set request.user, but guard defensively
    if (!user?._id) {
      throw unauthenticatedException()
    }

    const userId: string = user._id.toString()

    const isValidId = mongoose.Types.ObjectId.isValid(apiKeyId)
    if (!isValidId) {
      throw makeHttpException(
        ErrorCode.RESOURCE_NOT_FOUND,
        'Invalid API key id',
        HttpStatus.BAD_REQUEST,
      )
    }

    const apiKey = await this.authService.findApiKeyById(apiKeyId)

    if (!apiKey) {
      throw makeHttpException(
        ErrorCode.RESOURCE_NOT_FOUND,
        'API key not found',
        HttpStatus.NOT_FOUND,
      )
    }

    // Admin bypass
    if (user.role === UserRole.ADMIN) {
      return true
    }

    // Strict ownership check
    const keyOwnerId = apiKey.user?.toString()
    if (keyOwnerId === userId) {
      return true
    }

    throw forbiddenException(
      'You do not have permission to modify this API key',
    )
  }
}
