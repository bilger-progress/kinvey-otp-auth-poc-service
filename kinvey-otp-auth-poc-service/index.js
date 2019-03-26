"use-strict"

const kinveyFlexSdk = require("kinvey-flex-sdk");
const otplib = require("otplib");
const qrcode = require("qrcode");
const jsonwebtoken = require("jsonwebtoken");

const { version } = require("./package.json");

const OTP_USERS_COLLECTION = "otp-users";
const OTP_USER_IDENTIFIER = "emailAddress";
const OTP_USER_TOKEN_SECRET = "s3cr37";

function promisify(func) {
    return (...args) => {
        return new Promise((resolve, reject) => {
            func(...args, (error, data) => {
                if (error) {
                    return reject(error);
                }
                return resolve(data);
            });
        });
    };
}

function fetchUser(emailAddress, modules) {
    const findPromisified = promisify(modules.dataStore().collection(OTP_USERS_COLLECTION).find);
    return findPromisified(new modules.Query().equalTo(OTP_USER_IDENTIFIER, emailAddress))
        .then(data => data[0]);
}

kinveyFlexSdk.service((flexError, flexObj) => {
    if (flexError) {
        console.error("Error while initializing the Kinvey Flex service!");
        console.error(flexError);
        return;
    }

    flexObj.functions.register("registerOTPUser", (context, complete, modules) => {
        return fetchUser(context.body.emailAddress, modules)
            .then((data) => {
                if (data) {
                    console.error("#registerOTPUser: This User is already present in the collection!");
                    return complete().setBody({
                        success: false,
                        debug: "This User has already been registered!",
                        version
                    }).badRequest().done();
                }
                const savePromisified = promisify(modules.dataStore().collection(OTP_USERS_COLLECTION).save);
                return savePromisified({
                    emailAddress: context.body.emailAddress,
                    otpSecret: otplib.authenticator.generateSecret()
                });
            }).then((data) => {
                const otpUser = data.emailAddress;
                const otpService = "KinveyOTP";
                const otpSecret = data.otpSecret;
                const otpAuth = otplib.authenticator.keyuri(otpUser, otpService, otpSecret);
                const toDataURLPromisified = promisify(qrcode.toDataURL);
                return toDataURLPromisified(otpAuth);
            }).then((data) => {
                console.log("#registerOTPUser: Successful user registration.");
                return complete().setBody({
                    success: "true",
                    debug: "Successful user registration.",
                    version,
                    data
                }).ok().next();
            }).catch((error) => {
                console.error("#registerOTPUser: " + JSON.stringify(error));
                return complete().setBody({
                    success: false,
                    debug: "Error occured while trying to register a user. Please check logs.",
                    version
                }).runtimeError().done();
            });
    });

    flexObj.auth.register("authenticateOTPUser", (context, complete, modules) => {
        return fetchUser(context.body.username, modules)
            .then((data) => {
                if (!data) {
                    console.error("#authenticateOTPUser: This User is not present in the collection!");
                    return complete().accessDenied("User not registered!").done();
                }
                const isValid = otplib.authenticator.check(context.body.password, data.otpSecret);
                if (!isValid) {
                    console.error("#authenticateOTPUser: Something went wrong while authenticating the User.");
                    return complete().serverError("Something went wrong with the authentication process.").done();
                }
                console.log("#authenticateOTPUser: User successfully authenticated.");
                const token = jsonwebtoken.sign(
                    {
                        emailAddress: data.emailAddress
                    },
                    OTP_USER_TOKEN_SECRET,
                    {
                        expiresIn: 3600
                    }
                );
                return complete().setToken(token).ok().next();
            }).catch((error) => {
                console.error("#authenticateOTPUser: " + JSON.stringify(error));
                return complete().serverError("Something went wrong with the authentication process.").done();
            });
    });
});
