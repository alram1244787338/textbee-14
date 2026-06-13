import {
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { UsersService } from '../../users/users.service'
import { AuthService } from '../auth.service'
import * as bcrypt from 'bcryptjs'
import {
  accountBannedException,
  apiKeyRevokedException,
  unauthenticatedException,
} from '../../common/error-codes'

@Injectable()
// Guard for authenticating users by either jwt token or api key
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private usersService: UsersService,
    private authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()
    let userId: string | undefined
    let isApiKeyAuth = false

    const apiKeyString = request.headers['x-api-key'] || request.query.apiKey

    if (request.headers.authorization?.startsWith('Bearer ')) {
      const bearerToken = request.headers.authorization.split(' ')[1]
      try {
        const payload = this.jwtService.verify(bearerToken)
        userId = payload.sub
      } catch (e) {
        throw unauthenticatedException('Invalid or expired token')
      }
    } else if (apiKeyString) {
      // First try to find an active (non-revoked) key
      const activeApiKey =
        await this.authService.findActiveApiKeyByClientKey(apiKeyString)

      if (activeApiKey && bcrypt.compareSync(apiKeyString, activeApiKey.hashedApiKey)) {
        userId = activeApiKey.user?.toString()
        request.apiKey = activeApiKey
        isApiKeyAuth = true
      } else {
        // Check if the key exists but was revoked — return a distinct error
        // so clients can differentiate "wrong key" from "revoked key".
        const anyApiKey = await this.authService.findApiKey({
          apiKey: {
            $regex: new RegExp(`^${apiKeyString.substring(0, 17)}`),
          },
        })
        if (anyApiKey && bcrypt.compareSync(apiKeyString, anyApiKey.hashedApiKey)) {
          throw apiKeyRevokedException()
        }
        throw unauthenticatedException('Invalid API key')
      }
    }

    if (userId) {
      const user = await this.usersService.findOne({ _id: userId })
      if (user) {
        // Reject banned users with a clear, distinct error
        if (user.isBanned) {
          throw accountBannedException()
        }
        request.user = user
        this.authService.trackAccessLog({ request })
        return true
      }
    }

    throw unauthenticatedException()
  }
}
