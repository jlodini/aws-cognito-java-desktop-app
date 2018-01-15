/*
 * Copyright (c) 2018 Ryanair Ltd. All rights reserved.
 */
package com.amazonaws.sample.cognito.service;

public final class CognitoServiceConstants {

    private CognitoServiceConstants() { }

    /**
     * Indicates salt parameter for SRP authentication.
     */
    public static final String PARAM_SALT = "SALT";
    /**
     * Indicates secret block parameter.
     */
    public static final String PARAM_SECRET_BLOCK = "SECRET_BLOCK";
    /**
     * Indicates secret hash parameter.
     */
    public static final String PARAM_SECRET_HASH = "SECRET_HASH";
    /**
     * Indicates user-name parameter.
     */
    public static final String PARAM_USERNAME = "USERNAME";
    /**
     * Indicates HMACSHA256 algorithm parameter.
     */
    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    /**
     * Indicates HMAC algorithm parameter.
     */
    public static final String HMAC_ALGORITHM = "Hmac";
    /**
     * Indicates SHA1PRNG algorithm parameter.
     */
    public static final String SHA1PRNG_ALGORITHM = "SHA1PRNG";
    /**
     * Indicates SHA1PRNG algorithm parameter.
     */
    public static final String SHA256_ALGORITHM = "SHA-256";

    /**
     * Indicates UTM Time Zone parameter.
     */
    public static final String PARAM_UTC_TIME = "UTC";
    /**
     * Indicates parameter for internal user-name.
     */
    public static final String PARAM_USER_ID_FOR_SRP = "USER_ID_FOR_SRP";
    /**
     * Indicates time-stamp response parameter.
     */
    public static final String RESP_TIMESTAMP = "TIMESTAMP";
    /**
     * Indicates a SRP response parameter.
     */
    public static final String RESP_PASSWORD_CLAIM_SECRET_BLOCK = "PASSWORD_CLAIM_SECRET_BLOCK";
    /**
     * Indicates a SRP response parameter.
     */
    public static final String RESP_PASSWORD_CLAIM_SIGNATURE = "PASSWORD_CLAIM_SIGNATURE";
    /**
     * Indicates a SRP_A response parameter.
     */
    public static final String PARAM_SRP_A = "SRP_A";
    /**
     * Indicates the SRP parameter type.
     */
    public static final String PARAM_SRP_B = "SRP_B";

}
