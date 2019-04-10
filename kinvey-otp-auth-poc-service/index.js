"use-strict"

// External dependencies.
const kinveyFlexSdk = require("kinvey-flex-sdk");
const otplib = require("otplib");
const qrcode = require("qrcode");
const jsonwebtoken = require("jsonwebtoken");
const crypto = require("crypto");
const moment = require("moment");

// Get the service version, and return it with each request/response cycle.
const { version } = require("./package.json");

// Constants re-used within the auth process.
const OTP_USERS_COLLECTION = "otp-users";
const OTP_USER_IDENTIFIER = "emailAddress";
// Extermely not secure. :)
const OTP_USER_TOKEN_SECRET = "s3cr37";
const OTP_SERVICE_NAME = "KinveyOTP";
const OTP_SERVICE_EMAIL = "kinvey@kinvey.kinvey";

// TODO: Might want to save the "expiresAt" date/time instead of saving "issuedAt" date/time. 
const lessThanOneHourAgo = (date) => {
    return moment(date).isAfter(moment().subtract(1, "hours"));
}

/**
 * Turns callback executions into promises.
 * 
 * @param { Function } func 
 */
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

/**
 * Based on the received User data, it will return
 * a promise for generating a QR code URL.
 * 
 * @param { Object } data 
 */
function generateQRURL(data) {
    const otpUser = data.emailAddress;
    const otpService = OTP_SERVICE_NAME;
    const otpSecret = data.otpSecret;
    const otpAuth = otplib.authenticator.keyuri(otpUser, otpService, otpSecret);
    const toDataURLPromisified = promisify(qrcode.toDataURL);
    return toDataURLPromisified(otpAuth);
}

/**
 * Fetch User's data from the Kinvey 
 * collection.
 * 
 * @param { String } emailAddress 
 * @param { Object } modules 
 */
function getUser(emailAddress, modules) {
    const findPromisified = promisify(modules.dataStore().collection(OTP_USERS_COLLECTION).find);
    return findPromisified(new modules.Query().equalTo(OTP_USER_IDENTIFIER, emailAddress))
        .then(data => data[0]);
}

/**
 * Gracefully end a function call.
 * 
 * @param { Object } complete
 * @param { String } debug
 * @param { String } log
 * @param { String } data
 */
function endSuccess(complete, debug, log, data) {
    console.log(log);
    complete().setBody({
        success: true,
        debug,
        version,
        data
    }).ok().next();
}

/**
 * Fail a function call.
 * 
 * @param { Object } complete 
 * @param { String } debug 
 * @param { String } log 
 */
function endFailure(complete, debug, log) {
    console.error(log);
    complete().setBody({
        success: false,
        debug,
        version
    }).runtimeError().done();
}

// Set-up the Flex service.
kinveyFlexSdk.service((flexError, flexObj) => {
    if (flexError) {
        console.error("Error while initializing the Kinvey Flex service!");
        console.error(flexError);
        return;
    }

    // ------------------------------------------------------------
    //                      Flex Auth
    // ------------------------------------------------------------

    flexObj.auth.register("authenticateOTPUser", (context, complete, modules) => {
        getUser(context.body.username, modules)
            .then((data) => {
                if (!data) {
                    throw new Error("User not present.")
                }
                // Check if the passed OTP has been generated for this particular secret.
                const isValid = otplib.authenticator.check(context.body.password, data.otpSecret);
                if (!isValid) {
                    throw new Error("Could not authenticate.");
                }
                // Success. Sign a token.
                const token = jsonwebtoken.sign(
                    {
                        emailAddress: data.emailAddress
                    },
                    OTP_USER_TOKEN_SECRET,
                    {
                        expiresIn: 3600
                    }
                );
                console.log("#authenticateOTPUser: User successfully authenticated.");
                complete().setToken(token).ok().next();
            }).catch((error) => {
                console.error("#authenticateOTPUser: " + error);
                complete().accessDenied("Something went wrong with the authentication process. Please check logs").done();
            });
    });

    // ------------------------------------------------------------
    //                      Flex Functions
    // ------------------------------------------------------------

    flexObj.functions.register("registerOTPUser", (context, complete, modules) => {
        getUser(context.body.emailAddress, modules)
            .then((data) => {
                if (data) {
                    throw new Error("User already present.");
                }
                // Initially save User.
                const savePromisified = promisify(modules.dataStore().collection(OTP_USERS_COLLECTION).save);
                return savePromisified({
                    emailAddress: context.body.emailAddress,
                    otpSecret: otplib.authenticator.generateSecret()
                });
            }).then(
                // Generate a QR URL.
                data => generateQRURL(data)
            ).then(
                // Send back the QR URL.
                data => endSuccess(complete, "Successful user registration.", "#registerOTPUser: Successful user registration.", data)
            ).catch(
                error => endFailure(complete, "Error occured while trying to register a user. Please check logs.", "#registerOTPUser: " + error)
            );
    });

    flexObj.functions.register("resetOTPUser", (context, complete, modules) => {
        // Make sure that this call is made with Master Secret.
        const auth = (context.headers.authorization).replace("Basic ", "");
        const authBuf = Buffer.from(auth, "base64").toString();
        const isAuthValid = authBuf === modules.backendContext.getAppKey() + ":" + modules.backendContext.getMasterSecret();
        if (!isAuthValid) {
            return endFailure(complete, "Unauthorized to perform operation.", "#resetOTPUser: Request not made with Master Secret.");
        }
        let token = null;
        getUser(context.body.emailAddress, modules)
            .then((data) => {
                if (!data) {
                    throw new Error("User not present.");
                }
                // Add a new token for OTP resetting.
                data.resetOTPUserTokens = data.resetOTPUserTokens || [];
                token = crypto.randomBytes(60).toString("hex");
                // Make sure to add at the beginning of the array.
                data.resetOTPUserTokens.unshift({
                    token,
                    issuedAt: new moment().toISOString()
                });
                // Save entity.
                const savePromisified = promisify(modules.dataStore().collection(OTP_USERS_COLLECTION).save);
                return savePromisified(data);
            }).then((data) => {
                // Send this token to the User via e-mail.
                const sendPromisified = modules.email.send;
                return sendPromisified(OTP_SERVICE_EMAIL, data.emailAddress, "Reset OTP User",
                    "Please use the following code to re-set your OTP user account: " + token);
            }).then(
                data => endSuccess(complete, "Successful OTP user re-set.", "#resetOTPUser: " + JSON.stringify(data), null)
            ).catch(
                error => endFailure(complete, "Error occured while trying to re-set an OTP user. Please check logs.", "#resetOTPUser: " + error)
            );
    });

    flexObj.functions.register("regenerateOTPUser", (context, complete, modules) => {
        getUser(context.body.emailAddress, modules)
            .then((data) => {
                if (!data) {
                    throw new Error("User not present.");
                }
                // Prepare for searching that particular token.
                let found = false;
                data.resetOTPUserTokens.some((item, index) => {
                    if (item.token === context.body.token && lessThanOneHourAgo(item.issuedAt)) {
                        // Token found and it is valid.
                        found = true;
                        console.log(`#regenerateOTPUser: Found the item at index ${index}.`);
                    }
                    // This will stop the loop.
                    return found;
                });
                if (!found) {
                    throw new Error("Non-existing or expired token.");
                }
                // Save a new secret.
                const savePromisified = promisify(modules.dataStore().collection(OTP_USERS_COLLECTION).save);
                data.otpSecret = otplib.authenticator.generateSecret();
                return savePromisified(data);
            }).then(
                // Generate new QR URL.
                data => generateQRURL(data)
            ).then(
                // Return the new QR URL.
                data => endSuccess(complete, "Successful user re-generation.", "#regenerateOTPUser: Successful user re-generation.", data)
            ).catch(
                error => endFailure(complete, "Error occured while trying to re-generate the user. Please check logs.", "#regenerateOTPUser: " + error)
            );
    });
});
