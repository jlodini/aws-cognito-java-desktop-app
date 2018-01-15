package com.amazonaws.sample.cognito.service;

/*
 *  Copyright 2013-2016 Amazon.com,
 *  Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Amazon Software License (the "License").
 *  You may not use this file except in compliance with the
 *  License. A copy of the License is located at
 *
 *      http://aws.amazon.com/asl/
 *
 *  or in the "license" file accompanying this file. This file is
 *  distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 *  CONDITIONS OF ANY KIND, express or implied. See the License
 *  for the specific language governing permissions and
 *  limitations under the License.
 */

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.sample.cognito.util.Constants;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentity;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClientBuilder;
import com.amazonaws.services.cognitoidentity.model.Credentials;
import com.amazonaws.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import com.amazonaws.services.cognitoidentity.model.GetCredentialsForIdentityResult;
import com.amazonaws.services.cognitoidentity.model.GetIdRequest;
import com.amazonaws.services.cognitoidentity.model.GetIdResult;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpResult;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.InitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.util.Base64;
import com.amazonaws.util.StringUtils;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.SimpleTimeZone;

/**
 * The CognitoUser class abstracts the functionality of connecting to the Cognito user pool and Federated Identities.
 */
public class CognitoUser {

    private static final int SRP_RADIX = 16;

    private String poolId;
    private String clientAppId;
    private String secretKey;
    private String region;
    private String FED_POOL_ID;
    private String CUSTOMDOMAIN;

    public CognitoUser() {

        Properties prop = new Properties();
        InputStream input = null;

        try {
            input = getClass().getClassLoader().getResourceAsStream("config.properties");

            // load a properties file
            prop.load(input);

            // Read the property values
            poolId = prop.getProperty("POOL_ID");
            clientAppId = prop.getProperty("CLIENTAPP_ID");
            FED_POOL_ID = prop.getProperty("FED_POOL_ID");
            CUSTOMDOMAIN = prop.getProperty("CUSTOMDOMAIN");
            region = prop.getProperty("REGION");
            secretKey = prop.getProperty("SECRET");

        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public String GetHostedSignInURL() {
        String customurl = "https://%s.auth.%s.amazoncognito.com/login?response_type=code&client_id=%s&redirect_uri=%s";

        return String.format(customurl, CUSTOMDOMAIN, region, clientAppId, Constants.REDIRECT_URL);
    }

    public String GetTokenURL() {
        String customurl = "https://%s.auth.%s.amazoncognito.com/oauth2/token";

        return String.format(customurl, CUSTOMDOMAIN, region);
    }

    /**
     * Sign up the user to the user pool
     *
     * @param username    User name for the sign up
     * @param password    Password for the sign up
     * @param email       email used to sign up
     * @param phonenumber phone number to sign up.
     * @return whether the call was successful or not.
     */
    public boolean SignUpUser(String username, String password, String email, String phonenumber) {

        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(region))
                .build();

        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setClientId(clientAppId);
        signUpRequest.setUsername(username);
        signUpRequest.setPassword(password);
        signUpRequest.setSecretHash(this.calculateSecretHash(clientAppId, secretKey, username));

        List<AttributeType> list = new ArrayList<>();

        AttributeType attributeType = new AttributeType();
        attributeType.setName("phone_number");
        attributeType.setValue(phonenumber);
        list.add(attributeType);

        AttributeType attributeType1 = new AttributeType();
        attributeType1.setName("email");
        attributeType1.setValue(email);
        list.add(attributeType1);

        signUpRequest.setUserAttributes(list);

        try {
            SignUpResult result = cognitoIdentityProvider.signUp(signUpRequest);
            System.out.println(result);
        } catch (Exception e) {
            System.out.println(e);
            return false;
        }
        return true;
    }

    /**
     * Verify the verification code sent on the user phone.
     *
     * @param username User for which we are submitting the verification code.
     * @param code     Verification code delivered to the user.
     * @return if the verification is successful.
     */
    public boolean VerifyAccessCode(String username, String code) {
        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(region))
                .build();

        ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest();
        confirmSignUpRequest.setUsername(username);
        confirmSignUpRequest.setConfirmationCode(code);
        confirmSignUpRequest.setClientId(clientAppId);
        confirmSignUpRequest.setSecretHash(this.calculateSecretHash(clientAppId, secretKey, username));

        System.out.println("username=" + username);
        System.out.println("code=" + code);
        System.out.println("clientid=" + clientAppId);

        try {
            ConfirmSignUpResult confirmSignUpResult = cognitoIdentityProvider.confirmSignUp(confirmSignUpRequest);
            System.out.println("confirmSignupResult=" + confirmSignUpResult.toString());
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
        return true;
    }

    /**
     * Helper method to validate the user
     *
     * @param username represents the username in the cognito user pool
     * @param password represents the password in the cognito user pool
     * @return returns the JWT token after the validation
     */
    public String ValidateUser(String username, String password) throws Exception {
        return this.authenticate(username, password);
    }

    /**
     * Returns the AWS credentials
     *
     * @param idprovider the IDP provider for the login map
     * @param id         the username for the login map.
     * @return returns the credentials based on the access token returned from the user pool.
     */
    public Credentials GetCredentials(String idprovider, String id) {
        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AmazonCognitoIdentity provider = AmazonCognitoIdentityClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(region))
                .build();

        GetIdRequest idrequest = new GetIdRequest();
        idrequest.setIdentityPoolId(FED_POOL_ID);
        idrequest.addLoginsEntry(idprovider, id);
        GetIdResult idResult = provider.getId(idrequest);

        GetCredentialsForIdentityRequest request = new GetCredentialsForIdentityRequest();
        request.setIdentityId(idResult.getIdentityId());
        request.addLoginsEntry(idprovider, id);

        GetCredentialsForIdentityResult result = provider.getCredentialsForIdentity(request);
        return result.getCredentials();
    }

    /**
     * Returns the AWS credentials
     *
     * @param accesscode access code
     * @return returns the credentials based on the access token returned from the user pool.
     */
    public Credentials GetCredentials(String accesscode) {
        Credentials credentials = null;

        try {
            Map<String, String> httpBodyParams = new HashMap<String, String>();
            httpBodyParams.put(Constants.TOKEN_GRANT_TYPE, Constants.TOKEN_GRANT_TYPE_AUTH_CODE);
            httpBodyParams.put(Constants.DOMAIN_QUERY_PARAM_CLIENT_ID, clientAppId);
            httpBodyParams.put(Constants.DOMAIN_QUERY_PARAM_REDIRECT_URI, Constants.REDIRECT_URL);
            httpBodyParams.put(Constants.TOKEN_AUTH_TYPE_CODE, accesscode);

            AuthHttpClient httpClient = new AuthHttpClient();
            URL url = new URL(GetTokenURL());
            String result = httpClient.httpPost(url, httpBodyParams);
            System.out.println(result);

            JSONObject payload = CognitoJWTParser.getPayload(result);
            String provider = payload.get("iss").toString().replace("https://", "");
            credentials = GetCredentials(provider, result);

            return credentials;
        } catch (Exception exp) {
            System.out.println(exp);
        }
        return credentials;
    }

    /**
     * Start reset password procedure by sending reset code
     *
     * @param username user to be reset
     * @return returns code delivery details
     */
    public String ResetPassword(String username) {
        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(region))
                .build();

        ForgotPasswordRequest forgotPasswordRequest = new ForgotPasswordRequest();
        forgotPasswordRequest.setUsername(username);
        forgotPasswordRequest.setClientId(clientAppId);
        ForgotPasswordResult forgotPasswordResult = new ForgotPasswordResult();

        try {
            forgotPasswordResult = cognitoIdentityProvider.forgotPassword(forgotPasswordRequest);
        } catch (Exception e) {
            // handle exception here
        }
        return forgotPasswordResult.toString();
    }

    /**
     * complete reset password procedure by confirming the reset code
     *
     * @param username user to be reset
     * @param newpw    new password of aforementioned user
     * @param code     code sent for password reset from the ResetPassword() method above
     * @return returns code delivery details
     */
    public String UpdatePassword(String username, String newpw, String code) {
        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(region))
                .build();

        ConfirmForgotPasswordRequest confirmPasswordRequest = new ConfirmForgotPasswordRequest();
        confirmPasswordRequest.setUsername(username);
        confirmPasswordRequest.setPassword(newpw);
        confirmPasswordRequest.setConfirmationCode(code);
        confirmPasswordRequest.setClientId(clientAppId);
        ConfirmForgotPasswordResult confirmPasswordResult = new ConfirmForgotPasswordResult();

        try {
            confirmPasswordResult = cognitoIdentityProvider.confirmForgotPassword(confirmPasswordRequest);
        } catch (Exception e) {
            // handle exception here
        }
        return confirmPasswordResult.toString();
    }


    /**
     * This method returns the details of the user and bucket lists.
     *
     * @param credentials Credentials to be used for displaying buckets
     * @return
     */
    public String ListBucketsForUser(Credentials credentials) {

        BasicSessionCredentials awsCreds = new BasicSessionCredentials(credentials.getAccessKeyId(), credentials.getSecretKey(), credentials.getSessionToken());

        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(region))
                .build();

        StringBuilder bucketslist = new StringBuilder();

        bucketslist.append("===========Credentials Details.=========== \n");
        bucketslist.append("Accesskey = " + credentials.getAccessKeyId() + "\n");
        bucketslist.append("Secret = " + credentials.getSecretKey() + "\n");
        bucketslist.append("SessionToken = " + credentials.getSessionToken() + "\n");
        bucketslist.append("============Bucket Lists===========\n");

        for (Bucket bucket : s3Client.listBuckets()) {
            bucketslist.append(bucket.getName());
            bucketslist.append("\n");

            System.out.println(" - " + bucket.getName());
        }
        return bucketslist.toString();
    }

    /**
     * Method to orchestrate the SRP Authentication
     *
     * @param username Username for the SRP request
     * @param password Password for the SRP request
     * @return the JWT token if the request is successful else null.
     */
    public String authenticate(final String username, final String password) throws Exception {
        String authresult = null;

        final AuthenticationHelper authenticationHelper = new AuthenticationHelper(this.poolId);
        InitiateAuthRequest initiateAuthRequest = initiateUserSrpAuthRequest(username, authenticationHelper);
        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion(Regions.fromName(this.region))
                .build();

        InitiateAuthResult initiateAuthResult = cognitoIdentityProvider.initiateAuth(initiateAuthRequest);

        if (ChallengeNameType.PASSWORD_VERIFIER.toString().equals(initiateAuthResult.getChallengeName())) {

            RespondToAuthChallengeRequest challengeRequest =
                    userSrpAuthRequest(initiateAuthResult, password, authenticationHelper);
            RespondToAuthChallengeResult result = cognitoIdentityProvider.respondToAuthChallenge(challengeRequest);
            authresult = result.getAuthenticationResult().getIdToken();
        }

        return authresult;
    }

    /**
     * Initialize the authentication request for the first time.
     *
     * @param username The user for which the authentication request is created.
     * @return the Authentication request.
     */
    private InitiateAuthRequest initiateUserSrpAuthRequest(final String username,
                                                           final AuthenticationHelper authenticationHelper) {

        InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest();
        initiateAuthRequest.setAuthFlow(AuthFlowType.USER_SRP_AUTH);
        initiateAuthRequest.setClientId(this.clientAppId);
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.PARAM_SECRET_HASH,
                this.calculateSecretHash(this.clientAppId, this.secretKey, username));
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.PARAM_USERNAME, username);
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.PARAM_SRP_A,
                authenticationHelper.getA().toString(SRP_RADIX));
        return initiateAuthRequest;
    }

    /**
     * Method is used to respond to the Auth challange from the user pool
     *
     * @param challenge The authenticaion challange returned from the cognito user pool
     * @param password  The password to be used to respond to the authentication challenge.
     * @return the Request created for the previous authentication challenge.
     */
    private RespondToAuthChallengeRequest userSrpAuthRequest(final InitiateAuthResult challenge,
                                                             final String password,
                                                             final AuthenticationHelper authenticationHelper) {

        String userIdForSRP = challenge.getChallengeParameters()
                .get(CognitoServiceConstants.PARAM_USER_ID_FOR_SRP);
        String usernameInternal = challenge.getChallengeParameters().get(CognitoServiceConstants.PARAM_USERNAME);
        String secretHash = calculateSecretHash(this.clientAppId, this.secretKey, userIdForSRP);

        BigInteger srpB = new BigInteger(challenge.getChallengeParameters()
                .get(CognitoServiceConstants.PARAM_SRP_B), SRP_RADIX);
        if (srpB.mod(authenticationHelper.getN()).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(challenge.getChallengeParameters()
                .get(CognitoServiceConstants.PARAM_SALT), SRP_RADIX);
        byte[] key = authenticationHelper.getPasswordAuthenticationKey(userIdForSRP, password, srpB, salt);

        Date timestamp = new Date();
        byte[] hmac = null;

        String dateString;
        try {
            Mac mac = Mac.getInstance(CognitoServiceConstants.HMAC_SHA256_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, CognitoServiceConstants.HMAC_SHA256_ALGORITHM);
            mac.init(keySpec);
            mac.update(this.poolId.split("_", 2)[1].getBytes(StringUtils.UTF8));
            mac.update(userIdForSRP.getBytes(StringUtils.UTF8));

            byte[] secretBlock = Base64.decode(challenge.getChallengeParameters()
                    .get(CognitoServiceConstants.PARAM_SECRET_BLOCK));
            mac.update(secretBlock);

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(
                    SimpleTimeZone.UTC_TIME, CognitoServiceConstants.PARAM_UTC_TIME));

            dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes(StringUtils.UTF8);

            hmac = mac.doFinal(dateBytes);

        } catch (final Exception e) {
            throw new SecurityException("SRP error", e);
        }

        Map<String, String> srpAuthResponses = new HashMap<>();
        srpAuthResponses.put(CognitoServiceConstants.RESP_PASSWORD_CLAIM_SECRET_BLOCK,
                challenge.getChallengeParameters()
                        .get(CognitoServiceConstants.PARAM_SECRET_BLOCK));
        srpAuthResponses.put(CognitoServiceConstants.RESP_PASSWORD_CLAIM_SIGNATURE,
                new String(com.amazonaws.util.Base64.encode(hmac), StringUtils.UTF8));
        srpAuthResponses.put(CognitoServiceConstants.RESP_TIMESTAMP, dateString);
        srpAuthResponses.put(CognitoServiceConstants.PARAM_USERNAME, usernameInternal);

        if (this.secretKey != null) {
            srpAuthResponses.put(CognitoServiceConstants.PARAM_SECRET_HASH, secretHash);
        }

        RespondToAuthChallengeRequest authChallengeRequest = new RespondToAuthChallengeRequest();
        authChallengeRequest.setChallengeName(challenge.getChallengeName());
        authChallengeRequest.setClientId(this.clientAppId);
        authChallengeRequest.setSession(challenge.getSession());
        authChallengeRequest.setChallengeResponses(srpAuthResponses);

        return authChallengeRequest;
    }

    /**
     * Generates secret hash. Uses HMAC SHA256.
     *
     * @param userPoolClientId     REQUIRED: User ID
     * @param userPoolClientSecret REQUIRED: Client ID
     * @param userName             REQUIRED: Client secret
     * @return secret hash as a {@code String}, {@code null } if {@code clinetSecret if null}
     */
    public static String calculateSecretHash(final String userPoolClientId,
                                             final String userPoolClientSecret,
                                             final String userName) {
        final String algorithm = CognitoServiceConstants.HMAC_SHA256_ALGORITHM;

        if (userName == null) {
            throw new SecurityException("user ID cannot be null");
        }

        if (userPoolClientId == null) {
            throw new SecurityException("client ID cannot be null");
        }

        // Return null as secret hash if clientSecret is null.
        if (userPoolClientSecret == null) {
            return null;
        }
        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                algorithm);
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new SecurityException("Error while calculating ");
        }
    }

}

