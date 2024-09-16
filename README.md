***********************# Simple Authentication Service #***********************
This project is a lightweight authentication service built with Golang that uses JWT (JSON Web Tokens) for token-based authentication. It includes features like user registration, login, token refresh, and logout, along with secured API endpoints that require valid access tokens for access.

Features
--> User Registration (SignUp)
--> User Login (SignIn)
--> Access Token & Refresh Token Management
--> Logout with Token Blacklisting
--> Secured API Endpoints with JWT Authentication
--> Endpoints
--> Public Endpoints
--> User SignUp

URL: /api/user/signup
Method: POST
Description: Register a new user by providing username, password, national code, and phone.
User SignIn

URL: /api/user/signin
Method: POST
Description: Log in using username and password to get access and refresh tokens.
Refresh Token

URL: /api/user/refresh-token
Method: POST
Description: Exchange a valid refresh token for a new access token.
Log Out

URL: /api/user/logout
Method: POST
Description: Log out the user by blacklisting the current access token and removing the refresh token.

**#Secured Endpoints#**
All endpoints under the /api/v1 group require a valid access token to access. Attach the JWT in the Authorization header as a bearer token.

--> Get User by ID

URL: /api/v1/user
Method: GET
Description: Retrieve user details by user ID.

--> Update User Profile

URL: /api/v1/user/update-profile
Method: PUT
Description: Update user profile details (e.g., username, phone).

**#Authentication Flow#**
--> SignUp: User creates an account by providing the required details.
--> SignIn: User logs in with valid credentials and receives an access token and a refresh token.
--> Access Token Usage: Use the access token to access secured endpoints. Attach it to the Authorization header as a bearer token.
--> Token Expiry: If the access token expires, the client can use the refresh token to get a new access token by calling /api/user/refresh-token.
--> Logout: When the user logs out, the access token is blacklisted and the refresh token is deleted.

**#Authentication Middleware#**
The /api/v1 routes are protected by the AuthMiddleware, which verifies the access token.
If the token is invalid, expired, or blacklisted, the request will be rejected with an Unauthorized response.


**#Swagger Url#**
http://localhost:3000/swagger/index.html