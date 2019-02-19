"use-strict"

const kinveyFlexSDK = require("kinvey-flex-sdk");
const OTPjs = require("otp.js");
const jsonWebToken = require('jsonwebtoken');

const { version: serviceVersion } = require("./package.json");

const OTP_USERS_COLLECTION = "otp-users";
const TOKEN_SECRET = "s3cr3t";

kinveyFlexSDK.service((err, flex) => {
    if (err) {
        console.log("Error while initializing Flex!");
        return;
    }

    flex.functions.register("registerUser", (context, complete, modules) => {
        return promisify((callback) => {
            return modules.dataStore().collection(OTP_USERS_COLLECTION).save({
                emailAddress: context.body.emailAddress
            }, callback);
        }).then((data) => {
            console.log(data);
            return complete().setBody({
                success: "true",
                debug: "Success. Please check logs.",
                serviceVersion: serviceVersion
            }).ok().next();
        }).catch((error) => {
            console.error(error);
            return complete().setBody({
                success: false,
                debug: "Error occured. Please check logs.",
                serviceVersion: serviceVersion
            }).runtimeError().done();
        });
    });

    flex.functions.register("generateOTP", (context, complete, modules) => {
        return promisify((callback) => {
            return modules.dataStore().collection(OTP_USERS_COLLECTION)
            .find(new modules.Query().equalTo("emailAddress", context.body.emailAddress), callback);
        }).then((data) => {
            if (!data[0]) {
                // User not present.
                console.error("This User is not present in the collection!");
                return complete().setBody({
                    success: false,
                    debug: "Error occured. Please check logs.",
                    serviceVersion: serviceVersion
                }).runtimeError().done();
            }
            // User is present. Continue generating OTP.
            const generatedCode = OTPjs.totp.gen({string:context.body.emailAddress},
                {time:30, timestamp:new Date().getTime(), codeDigits:6, addChecksum:false, algorithm:"sha1"});
            // Send OTP to that e-mail address.
            return promisify((callback) => {
                return modules.email.send("bilgerkinveytest@gmail.com", context.body.emailAddress, "Your OTP!", 
                "Your OTP is: " + generatedCode, callback);
            });
        }).then((data) => {
            console.log(data);
            return complete().setBody({
                success: "true",
                debug: "Success. Please check logs.",
                serviceVersion: serviceVersion
            }).ok().next();
        }).catch((error) => {
            console.error(error);
                return complete().setBody({
                    success: false,
                    debug: "Error occured. Please check logs.",
                    serviceVersion: serviceVersion
                }).runtimeError().done();
        });
    });

    flex.auth.register("verifyOTP", (context, complete, modules) => {
        try {
            // The Kinvey Backend expects username and password fields.
            const codeVerificationResult = OTPjs.totp.verify(context.body.password, {string:context.body.username},
                {window:1, time:30, timestamp:new Date().getTime(), addChecksum:false, algorithm:"sha1"});
                // Check if all is fine with the verification.
            if (!codeVerificationResult || typeof codeVerificationResult === "undefined") {
                console.error("Something went wrong while verifying the OTP.");
                console.error(codeVerificationResult);
                return complete().serverError("Something went wrong while verifying the OTP.").done();
            }
            // All should be fine.
            console.log(JSON.stringify(codeVerificationResult));
            const userToken = jsonWebToken.sign({username: context.body.username}, TOKEN_SECRET, {expiresIn: 3600});
            return complete().setToken({userToken: userToken}).ok().next();
        } catch (error) {
            console.error(error);
            return complete().serverError("Something went wrong while verifying the OTP.").done();
        }
    });
});

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