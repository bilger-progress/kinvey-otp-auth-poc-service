"use-strict"

const kinveyFlexSdk = require("kinvey-flex-sdk");
const otplib = require("otplib");
const qrcode = require("qrcode");

const { version: serviceVersion } = require("./package.json");

const OTP_USERS_COLLECTION = "otp-users";
const OTP_USER_IDENTIFIER = "emailAddress";

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

    flexObj.functions.register("registerUser", (context, complete, modules) => {
        return fetchUser(context.body.emailAddress, modules)
            .then((data) => {
                if (data) {
                    console.error("#registerUser: This User is already present in the collection!");
                    return complete().setBody({
                        success: false,
                        debug: "This User has already been registered!",
                        serviceVersion
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
                console.log("#registerUser: Successful user registration.");
                return complete().setBody({
                    success: "true",
                    debug: "Successful user registration.",
                    serviceVersion,
                    data
                }).ok().next();
            }).catch((error) => {
                console.error("#registerUser: " + JSON.stringify(error));
                return complete().setBody({
                    success: false,
                    debug: "Error occured while trying to register a user. Please check logs.",
                    serviceVersion
                }).runtimeError().done();
            });
    });
});
