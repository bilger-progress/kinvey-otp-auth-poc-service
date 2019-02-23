# kinvey-otp-auth-poc-service
Proof of Concept for One-Time-Password Auth on Kinvey.

## Architecture
The Proof-of-Concept project contains a single Kinvey app, and two Kinvey services:
  - Flex service - FSR runtime
  - Rapid(Auth) - MIC service - Flex Runtime(Auth) connector
  
1. Kinvey App
  - Contains a single data collection - meant to store the (registered) user's e-mail addresses.
  - Two publicly accessible custom endpoints:
    + `/registerUser` - for user registration
    + `/generateOTP` - for OTP generation for a user
2. Flex service - FSR runtime - registers three functions:
  - Flex function (HTTP trigger) - `registerUser`
    + This function makes sure to register users to the system with provided e-mail address.
  - Flex function (HTTP trigger) - `generateOTP`
    + This function makes sure to generate a OTP for a registered user. The OTP is sent to the user's address.
  - Flex auth (Auth service trigger) - `verifyOTP`
    + This function makes sure to verify that the provided OTP has been generated for that particular user (e-mail address). If yes, then a token is returned. 
3. Rapid(Auth) service (MIC)
  - Configured to use the `verifyOTP` function from the Flex service as an authentication method.
    
## External dependencies
1. One Time Password manager (https://www.npmjs.com/package/otp.js)
2. JSON Web Token manager (https://www.npmjs.com/package/jsonwebtoken)

## Detailed description
// TODO.

## Diagram
// TODO.
