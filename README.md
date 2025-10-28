# TikHub Cloud API

Cloud authentication and subscription management API for TikHub.

## Features

- User authentication (email/password + OAuth)
- Subscription management
- Rate limiting
- Database backups/restore
- Admin tools

## Deployment

This API is deployed on Render.com and automatically deploys when changes are pushed to the `main` branch.

## Environment Variables

Required environment variables (configured in Render.com):

- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret key for JWT tokens
- `SESSION_SECRET` - Secret key for sessions
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret
- `DISCORD_CLIENT_ID` - Discord OAuth client ID
- `DISCORD_CLIENT_SECRET` - Discord OAuth client secret
- `ADMIN_API_KEY` - Admin authentication key

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/verify` - Verify JWT token
- `GET /api/auth/google` - Google OAuth
- `GET /api/auth/discord` - Discord OAuth
- `POST /api/auth/reset-password` - Reset password

### Subscriptions
- `GET /api/subscription/status` - Get user subscription
- `POST /api/subscription/update` - Update subscription (admin)

### Admin
- `GET /api/admin/users` - List all users
- `POST /api/admin/update-subscription` - Update user subscription
- `GET /api/admin/backup` - Export database backup
- `POST /api/admin/restore` - Restore database from backup
- `POST /api/admin/generate-reset-token` - Generate password reset link

## License

Private - All Rights Reserved
