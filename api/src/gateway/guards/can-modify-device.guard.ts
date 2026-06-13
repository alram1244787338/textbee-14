import {
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common'
import mongoose from 'mongoose'
import { UserRole } from '../../users/user-roles.enum'
import { GatewayService } from '../gateway.service'
import {
  forbiddenException,
  unauthenticatedException,
  deviceNotFoundException,
} from '../../common/error-codes'

@Injectable()
export class CanModifyDevice implements CanActivate {
  constructor(private gatewayService: GatewayService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    const deviceId = request.params.id
    const user = request.user

    // AuthGuard should have already set request.user, but guard defensively
    if (!user?._id) {
      throw unauthenticatedException()
    }

    const userId: string = user._id.toString()

    const isValidId = mongoose.Types.ObjectId.isValid(deviceId)
    if (!isValidId) {
      throw deviceNotFoundException()
    }

    const device = await this.gatewayService.getDeviceById(deviceId)
    if (!device) {
      throw deviceNotFoundException()
    }

    // Admin bypass — admins can manage any device
    if (user.role === UserRole.ADMIN) {
      return true
    }

    // Strict ownership check — compare ObjectId string representations
    const deviceOwnerId = device.user?.toString()
    if (deviceOwnerId === userId) {
      return true
    }

    // Authenticated user who does not own the resource → 403, not 401
    throw forbiddenException(
      'You do not have permission to modify this device',
    )
  }
}
