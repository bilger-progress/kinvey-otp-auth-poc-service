"use-strict"

// External dependencies.
const kinveyFlexSDK = require("kinvey-flex-sdk");
const OTPjs = require("otp.js");
const jsonWebToken = require('jsonwebtoken');
const crypto = require("crypto");

// The service version is returned within the request/response cycle.
const { version: serviceVersion } = require("./package.json");
 
/**
 * The collection, which stores the OTP users.
 * This collection needs to be fully private. 
 * So all actions on it should be forbidden.
 * No Create, Read, Update, Delete.
 */
const OTP_USERS_COLLECTION = "otp-users";

// Random secret.
const TOKEN_SECRET = "s3cr3t";

// Initialize the Kinvey Flex service.
kinveyFlexSDK.service((flexError, flexObj) => {
    if (flexError) {
        console.error("Error while initializing the Kinvey Flex service!");
        console.error(flexError);
        return;
    }

    /**
     * Function, which will enable Users to register via
     * providing their e-mail addresses.
     */
    flexObj.functions.register("registerUser", (context, complete, modules) => {
        //Initially check if the User has already been registered.
        return promisify((callback) => {
            return modules.dataStore().collection(OTP_USERS_COLLECTION)
                .find(new modules.Query().equalTo("emailAddress", context.body.emailAddress), callback);
        }).then((data) => {
            if (data[0]) {
                // User present.
                console.error("#registerUser: This User is already present in the collection!");
                return complete().setBody({
                    success: false,
                    debug: "This User has already been registered!",
                    serviceVersion: serviceVersion
                }).badRequest().done();
            }
            // User not present. Go ahead.
            return promisify((callback) => {
                return modules.dataStore().collection(OTP_USERS_COLLECTION).save({
                    emailAddress: context.body.emailAddress,
                    otpSecret: crypto.randomBytes(30).toString("hex")
                }, callback);
            });
        }).then((data) => {
            console.log("#registerUser: " + JSON.stringify(data));
            return complete().setBody({
                success: "true",
                debug: "Successful User Registration. Please check logs.",
                serviceVersion: serviceVersion
            }).ok().next();
        }).catch((error) => {
            console.error("#registerUser: " + JSON.stringify(error));
            return complete().setBody({
                success: false,
                debug: "Error occured while trying to register a User. Please check logs.",
                serviceVersion: serviceVersion
            }).runtimeError().done();
        });
    });

    /**
     * Function, which will generate a 30-second valid OTP for a registered User.
     * The OTP will be sent to the e-mail address of the User.
     */
    flexObj.functions.register("generateOTP", (context, complete, modules) => {
        return promisify((callback) => {
            return modules.dataStore().collection(OTP_USERS_COLLECTION)
                .find(new modules.Query().equalTo("emailAddress", context.body.emailAddress), callback);
        }).then((data) => {
            if (!data[0]) {
                // User not present.
                console.error("#generateOTP: This User is not present in the collection!");
                return complete().setBody({
                    success: false,
                    debug: "This User is not present in the collection! Please check logs.",
                    serviceVersion: serviceVersion
                }).notFound().done();
            }
            // User is present. Continue generating OTP.
            let userObj = data[0];
            const generatedCode = OTPjs.totp.gen( { string : userObj.emailAddress + userObj.otpSecret },
                { time : 30, timestamp :new Date().getTime(), codeDigits : 6, addChecksum : false, algorithm : "sha1" } );
            // Send OTP to that e-mail address.
            return promisify((callback) => {
                return modules.email.send("kinvey@kinvey.com", context.body.emailAddress, "Your OTP!",
                    "Your OTP is: " + generatedCode, callback);
            });
        }).then((data) => {
            console.log("#generateOTP: " + JSON.stringify(data));
            return complete().setBody({
                success: "true",
                debug: "Your OTP has been sent to the e-mail address. Please check logs.",
                serviceVersion: serviceVersion
            }).ok().next();
        }).catch((error) => {
            console.error("#generateOTP: " + JSON.stringify(error));
            return complete().setBody({
                success: false,
                debug: "Error occured. Please check logs.",
                serviceVersion: serviceVersion
            }).runtimeError().done();
        });
    });

    /**
     * Function, which will verify the validity of a OTP for a particular User.
     * If OTP is valid, an access token will be signed and returned. The Kinvey 
     * Backend (MIC configuration) expects "username" and "password" fields. 
     * That's why the e-mail address and OTP code are masked as "username" and "password".
     */
    flexObj.auth.register("verifyOTP", (context, complete, modules) => {
        return promisify((callback) => {
            return modules.dataStore().collection(OTP_USERS_COLLECTION)
                .find(new modules.Query().equalTo("emailAddress", context.body.username), callback);
        }).then((data) => {
            if (!data[0]) {
                // User not present.
                console.error("#verifyOTP: This User is not present in the collection!");
                return complete().accessDenied("User not registered!").done();
            }
            // User is present. Continue verifying OTP.
            let userObj = data[0];
            const codeVerificationResult = OTPjs.totp.verify(context.body.password, { string : userObj.emailAddress + userObj.otpSecret },
                { window : 1, time : 30, timestamp : new Date().getTime(), addChecksum : false, algorithm : "sha1" } );
            // Check if all is fine with the verification.
            if (!codeVerificationResult || typeof codeVerificationResult === "undefined") {
                console.error("#verifyOTP: Something went wrong while verifying the OTP.");
                console.error("#verifyOTP: " + JSON.stringify(codeVerificationResult));
                return complete().serverError("Something went wrong while verifying the OTP.").done();
            }
            // All should be fine.
            console.log("#verifyOTP: " + JSON.stringify(codeVerificationResult));
            // Generate a token for this User.
            const userToken = jsonWebToken.sign( { emailAddress : userObj.emailAddress }, TOKEN_SECRET, { expiresIn : 3600 } );
            return complete().setToken(userToken).ok().next();
        }).catch((error) => {
            console.error("#verifyOTP: " + JSON.stringify(error));
            return complete().serverError("Something went wrong while verifying the OTP.").done();
        });
    });
});

/**
 * Used to chain callback executions as a
 * promise-fashioned process.
 * 
 * @param { Function } foo 
 */
const promisify = function (foo) {
    return new Promise(function (resolve, reject) {
        foo(function (error, result) {
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        });
    });
};
