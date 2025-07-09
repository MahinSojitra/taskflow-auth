# TaskFlowAuth API

A production-ready OAuth 2.0 and OpenID Connect authentication API built with Node.js, Express, and MongoDB.

## 🚀 Features

- **OAuth 2.0 & OpenID Connect** - Full implementation of OAuth 2.0 flows and OpenID Connect
- **JWT Tokens** - Access tokens, refresh tokens, and ID tokens with proper rotation
- **PKCE Support** - Proof Key for Code Exchange for enhanced security
- **Role-Based Access Control** - User roles and permissions system
- **Security Features** - Rate limiting, input validation, CORS, Helmet, and more
- **MongoDB Integration** - Mongoose ODM with comprehensive data models
- **API Documentation** - Swagger/OpenAPI documentation
- **Testing** - Jest unit tests with coverage reporting
- **Docker Support** - Production-ready Docker configuration
- **Logging** - Winston logging with file and console outputs

## 📋 Prerequisites

- Node.js 18+
- MongoDB 6.0+
- npm or yarn

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/taskflow-auth.git
cd taskflow-auth
```

### 2. Install dependencies

```bash
npm install
```

### 3. Environment Configuration

Copy the environment example file and configure your settings:

```bash
cp env.example .env
```

Edit `.env` with your configuration:

```env
# Server Configuration
NODE_ENV=development
PORT=3000
HOST=localhost

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/taskflow_auth
MONGODB_URI_TEST=mongodb://localhost:27017/taskflow_auth_test

# JWT Configuration
JWT_ACCESS_SECRET=your-super-secret-access-key-change-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-in-production
JWT_ID_SECRET=your-super-secret-id-key-change-in-production
```

### 4. Start MongoDB

Make sure MongoDB is running on your system or use Docker:

```bash
docker run -d -p 27017:27017 --name mongodb mongo:6.0
```

### 5. Run the application

```bash
# Development mode
npm run dev

# Production mode
npm start
```

The API will be available at `http://localhost:3000`

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# Start with development tools
docker-compose --profile dev up -d

# View logs
docker-compose logs -f taskflow-auth
```

### Using Docker directly

```bash
# Build the image
docker build -t taskflow-auth .

# Run the container
docker run -d \
  --name taskflow-auth \
  -p 3000:3000 \
  -e MONGODB_URI=mongodb://host.docker.internal:27017/taskflow_auth \
  taskflow-auth
```

## 📚 API Documentation

Once the server is running, you can access the interactive API documentation at:

- **Swagger UI**: `http://localhost:3000/api-docs`
- **OpenAPI Spec**: `http://localhost:3000/api-docs/swagger.json`

## 🔐 Authentication Endpoints

### User Registration

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe"
}
```

### User Login

```http
POST /auth/login
Content-Type: application/json

{
  "identifier": "user@example.com",
  "password": "SecurePass123!"
}
```

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

### Get User Profile

```http
GET /auth/profile
Authorization: Bearer your-access-token
```

## 🔄 OAuth 2.0 Endpoints

### Authorization Endpoint

```http
GET /oauth2/authorize?response_type=code&client_id=your-client-id&redirect_uri=http://localhost:3001/callback&scope=openid profile email&state=random-state
```

### Token Endpoint

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=authorization-code&redirect_uri=http://localhost:3001/callback&client_id=your-client-id&client_secret=your-client-secret
```

### UserInfo Endpoint

```http
GET /oauth2/userinfo
Authorization: Bearer your-access-token
```

### Token Revocation

```http
POST /oauth2/revoke
Content-Type: application/x-www-form-urlencoded

token=your-token&token_type_hint=access_token
```

## 🏢 Client Management

### Register OAuth2 Client

```http
POST /clients
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "name": "My Application",
  "description": "A sample OAuth2 client",
  "clientType": "confidential",
  "redirectUris": ["http://localhost:3001/callback"],
  "scopes": ["openid", "profile", "email"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "responseTypes": ["code"]
}
```

### Get User's Clients

```http
GET /clients
Authorization: Bearer your-access-token
```

## 🧪 Testing

### Run Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Test Coverage

The project includes comprehensive unit tests with coverage reporting. Coverage reports are generated in the `coverage/` directory.

## 🔧 Development

### Available Scripts

```bash
# Development
npm run dev          # Start development server with nodemon
npm run start        # Start production server

# Testing
npm test             # Run tests
npm run test:watch   # Run tests in watch mode
npm run test:coverage # Run tests with coverage

# Code Quality
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint issues

# Documentation
npm run docs:generate # Generate Swagger documentation
npm run docs:serve   # Serve documentation
```

### Project Structure

```
taskflow-auth/
├── src/
│   ├── config/          # Configuration files
│   ├── controllers/     # Route controllers
│   ├── middleware/      # Express middleware
│   ├── models/          # Mongoose models
│   ├── routes/          # API routes
│   ├── services/        # Business logic
│   ├── tests/           # Test files
│   ├── utils/           # Utility functions
│   └── server.js        # Main application file
├── logs/                # Application logs
├── coverage/            # Test coverage reports
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose configuration
├── jest.config.js       # Jest configuration
├── package.json         # Dependencies and scripts
└── README.md           # This file
```

## 🔒 Security Features

- **Helmet.js** - Security headers
- **CORS** - Cross-origin resource sharing
- **Rate Limiting** - Request rate limiting
- **Input Validation** - Express-validator for request validation
- **Password Hashing** - bcrypt with configurable rounds
- **JWT Security** - Secure token generation and validation
- **PKCE** - Proof Key for Code Exchange for public clients
- **Token Rotation** - Automatic refresh token rotation
- **NoSQL Injection Protection** - MongoDB query sanitization
- **HTTP Parameter Pollution Protection** - HPP middleware

## 🌐 OAuth 2.0 Flows Supported

1. **Authorization Code Flow** - Standard OAuth 2.0 flow
2. **Implicit Flow** - For public clients (deprecated but supported)
3. **Client Credentials Flow** - For server-to-server authentication
4. **Resource Owner Password Flow** - For trusted applications
5. **Refresh Token Flow** - Token refresh mechanism

## 🔐 OpenID Connect Features

- **ID Tokens** - JWT-based identity tokens
- **UserInfo Endpoint** - User profile information
- **Discovery Endpoint** - OpenID Connect configuration
- **JWKS Endpoint** - JSON Web Key Set
- **Logout Endpoint** - RP-initiated logout

## 📊 Monitoring and Logging

The application uses Winston for logging with the following features:

- **File Logging** - Logs stored in `logs/` directory
- **Console Logging** - Development environment
- **Log Levels** - Error, warn, info, debug
- **Log Rotation** - Automatic log file rotation
- **Structured Logging** - JSON format for production

## 🚀 Production Deployment

### Environment Variables

Make sure to set the following environment variables in production:

```env
NODE_ENV=production
JWT_ACCESS_SECRET=your-very-secure-access-secret
JWT_REFRESH_SECRET=your-very-secure-refresh-secret
JWT_ID_SECRET=your-very-secure-id-secret
MONGODB_URI=your-production-mongodb-uri
```

### Security Checklist

- [ ] Change all JWT secrets
- [ ] Use HTTPS in production
- [ ] Configure proper CORS origins
- [ ] Set up proper MongoDB authentication
- [ ] Configure rate limiting for your use case
- [ ] Set up monitoring and alerting
- [ ] Regular security updates
- [ ] Database backups

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- Create an issue on GitHub
- Check the API documentation at `/api-docs`
- Review the test files for usage examples

## 🙏 Acknowledgments

- [Express.js](https://expressjs.com/) - Web framework
- [Mongoose](https://mongoosejs.com/) - MongoDB ODM
- [Passport.js](http://www.passportjs.org/) - Authentication middleware
- [JWT](https://jwt.io/) - JSON Web Tokens
- [OAuth 2.0](https://oauth.net/2/) - Authorization framework
- [OpenID Connect](https://openid.net/connect/) - Identity layer
