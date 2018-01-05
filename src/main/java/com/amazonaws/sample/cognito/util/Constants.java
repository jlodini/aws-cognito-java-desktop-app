/*
 * Copyright 2013-2017 Amazon.com, Inc. or its affiliates.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.amazonaws.sample.cognito.util;

/**
 * Local SDK constants.
 */

@SuppressWarnings("checkstyle:javadocmethod")
public abstract class Constants {
    public static final String DOMAIN_QUERY_PARAM_CLIENT_ID = "client_id";

    public static final String DOMAIN_QUERY_PARAM_REDIRECT_URI = "redirect_uri";
    public static final String TOKEN_AUTH_TYPE_CODE = "code";
    public static final String TOKEN_GRANT_TYPE = "grant_type";
    public static final String TOKEN_GRANT_TYPE_AUTH_CODE = "authorization_code";

    public static final String HTTP_HEADER_PROP_CONTENT_TYPE = "Content-Type";
    public static final String HTTP_HEADER_PROP_CONTENT_TYPE_DEFAULT = "application/x-www-form-urlencoded";
    public static final String HTTP_REQUEST_TYPE_POST = "POST";
    public static final String REDIRECT_URL = "https://sid343.reinvent-workshop.com";

}