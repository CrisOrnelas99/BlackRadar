# 🔐 Users, Authentication, And Sessions

## 🧭 Overview

Authentication establishes who is making a request. Authorization determines what that identity may do. Session state makes access revocation possible after login.

BlackRadar uses user records, short-lived JWT access tokens, and server-side refresh sessions.

## 🔌 Current API

```text
POST /api/auth/register
POST /api/auth/login
POST /api/auth/refresh
POST /api/auth/logout
```

Protected application routes require a valid access token and an active corresponding refresh-session record.

## 🔄 Session Lifecycle

1. Registration validates full name, identity, and password fields, hashes the password, and assigns the default role.
2. Login accepts username or email plus password and returns access material only after credential verification.
3. The access JWT is short-lived and contains scoped claims.
4. The refresh token identifies server-side session state and is sent to the browser only as an HttpOnly cookie.
5. Refresh rotates the session and revokes the previous session.
6. Logout revokes the session so paired access requests fail session validation.

## 🧩 Layer Responsibilities

The user service owns credential workflow, token orchestration, and session lifecycle. Repositories own user and refresh-session persistence. JWT primitives validate signatures and claims. Middleware establishes the authenticated principal for protected requests.

The browser keeps the access token in memory. The refresh token is stored in an HttpOnly cookie so JavaScript cannot read it, and backend revocation remains authoritative.

## 🛡️ Security Invariants

- Passwords are stored as bcrypt hashes, never plaintext.
- JWT secrets must satisfy minimum configuration requirements.
- Access and refresh tokens have distinct scopes and uses.
- Refresh sessions are server-side and revocable.
- Roles are not client-controlled registration fields.
- Invalid login responses remain generic.
- Protected routes require backend middleware; Angular guards are UX only.

See [security-boundaries.md](security-boundaries.md) and [api-error-handling.md](api-error-handling.md).

## 🎭 Walkthrough: Alice Logs In

1. Alice has a registered account; Bob is another user with separate session state.
2. Alice exchanges valid credentials for an access token and refresh session.
3. The login request reaches the authentication controller.
4. The service validates credentials, the repository reads user/session data, and middleware later validates tokens on protected routes.
5. Requests need a server-verifiable identity without trusting user IDs or permissions supplied by the browser.
6. The server verifies the password, issues short-lived access credentials, stores revocable refresh state, and returns generic failures when authentication is invalid.

The authenticated user summary includes the full name, username, and email. The frontend uses the full name for the dashboard and account label, then falls back to username or email when an older account has no full name.

## 🚧 Current Limitations

- Organization membership is not part of the current authentication contract.
- Production deployments must keep refresh cookies `Secure`, use restrictive CORS origins, and add CSRF protection before relaxing same-site cookie behavior.
- Device/session management UI and audit history are future work.

## 🔑 Key Terms

- **Authentication:** Establishing the identity behind a request.
- **Authorization:** Deciding whether an authenticated identity may perform an action.
- **Access token:** Short-lived JWT used for API authorization.
- **Refresh session:** Server-side revocable state associated with refresh capability.
- **Rotation:** Replacing a refresh session while revoking the prior one.
