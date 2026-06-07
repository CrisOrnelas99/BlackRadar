# SecureOps Lite Go Backend

This is the main Go backend for SecureOps Lite.

It now uses:

- Gin for routing and HTTP middleware
- GORM for PostgreSQL persistence

It follows the same current backend logic:

- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- JWT-protected asset and vulnerability routes
- basic `RequestFilter` request blocking
- asset CRUD
- user-scoped asset ownership
- vulnerability CRUD
- asset-to-vulnerability assignment
- GORM AutoMigrate for database schema provisioning at startup

This backend is the main API and trust boundary for the application.

## Structure

The layout keeps the backend packages at the project root for a simple application structure:

```text
backend-Go/
|-- main/
|   |-- main.go
|   `-- api/
|       |-- config/
|       |-- controller/
|       |-- dto/
|       |-- middleware/
|       |-- model/
|       |-- repository/
|       |-- security/
|       |-- service/
|       `-- utils/

```

Package roles:

- `controller/`: Gin handlers
- `service/`: business logic
- `repository/`: GORM persistence
- `dto/`: request/response structs
- `model/`: database/domain models
- `security/`: JWT generation and authentication middleware
- `middleware/`: request pipeline middleware such as `RequestFilter`
- `utils/`: PostgreSQL connection helpers and database error helpers

## Environment

The service reads these environment values:

- `DB_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `JWT_SECRET`
- `JWT_EXPIRATION_MS`

Default backend port: `8080`.
