/*
 * Copyright 2014 Uwe Trottmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.uwetrottmann.trakt.v2;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import retrofit.RequestInterceptor;
import retrofit.RestAdapter;

public class TraktV2 {

    /**
     * trakt API v2 URL.
     */
    public static final String API_URL = "https://beta-api.trakt.tv";

    public static final String OAUTH2_AUTHORIZATION_URL = "";
    public static final String OAUTH2_TOKEN_URL = "";

    /**
     * Builds an OAuth 2.0 authorization request to obtain an authorization code.
     *
     * <p> Send the user to the location URI of this request. Once the user authorized your app,
     * the server will redirect to {@code redirectUri} with the authorization code in the query
     * parameter {@code code}.
     * <p> Supply the authorization code to {@link #getAccessToken(String, String, String, String)}
     * to get an access token.
     */
    public static OAuthClientRequest buildAuthorizationRequest(String clientId, String redirectUri)
            throws OAuthSystemException {
        return OAuthClientRequest
                .authorizationLocation(OAUTH2_AUTHORIZATION_URL)
                .setResponseType(ResponseType.CODE.toString())
                .setClientId(clientId)
                .setRedirectURI(redirectUri)
                .buildQueryMessage();
    }

    public static OAuthClientRequest buildAccessTokenRequest(String clientId, String clientSecret,
            String redirectUri, String authCode) throws OAuthSystemException {
        return OAuthClientRequest
                .tokenLocation(OAUTH2_TOKEN_URL)
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setCode(authCode)
                .setRedirectURI(redirectUri)
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .buildQueryMessage();
    }

    public static OAuthClientRequest buildRefreshAccessTokenRequest(String clientId,
            String clientSecret, String redirectUri, String refreshToken)
            throws OAuthSystemException {
        return OAuthClientRequest
                .tokenLocation(OAUTH2_TOKEN_URL)
                .setGrantType(GrantType.REFRESH_TOKEN)
                .setCode(refreshToken)
                .setRedirectURI(redirectUri)
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .buildQueryMessage();
    }

    /**
     * Requests a new OAuth 2.0 access token from the server using an authorization code.
     *
     * <p> Supply the received access token to {@link #setAccessToken(String)}. Once the access
     * token has expired, use the received refresh token to request a new one with
     * {@link #refreshAccessToken(String, String, String, String)}.
     *
     * <p> On failure re-authorization of your app is required (see {@link
     * #buildAuthorizationRequest(String, String)}).
     *
     * @param authCode A valid authorization code (see {@link
     *                 #buildAuthorizationRequest(String, String)}).
     */
    public static OAuthAccessTokenResponse getAccessToken(String clientId,
            String clientSecret, String redirectUri, String authCode)
            throws OAuthSystemException, OAuthProblemException {
        OAuthClientRequest request = buildAccessTokenRequest(clientId, clientSecret, redirectUri,
                authCode);

        OAuthClient client = new OAuthClient(new URLConnectionClient());
        return client.accessToken(request);
    }

    /**
     * Requests a new OAuth 2.0 access token from the server using a refresh token issued together
     * with a past access token.
     *
     * <p> On failure re-authorization of your app is required (see {@link
     * #buildAuthorizationRequest(String, String)}).
     *
     * @param refreshToken A refresh token obtained with a past access token.
     */
    public static OAuthAccessTokenResponse refreshAccessToken(String clientId,
            String clientSecret, String redirectUri, String refreshToken)
            throws OAuthSystemException, OAuthProblemException {
        OAuthClientRequest request = buildRefreshAccessTokenRequest(clientId, clientSecret,
                redirectUri, refreshToken);

        OAuthClient client = new OAuthClient(new URLConnectionClient());
        return client.accessToken(request);
    }

    private String mAccessToken;

    private boolean mIsDebug;

    /**
     * Currently valid instance of RestAdapter.
     */
    private RestAdapter mRestAdapter;

    /**
     * Get a new API manager instance.
     *
     * <p> Re-use this instance instead of calling this constructor again.
     */
    public TraktV2() {
    }

    /**
     * Sets the OAuth 2.0 access token for your user to be appended to requests.
     *
     * <p> If set, some endpoints will return user-specific data.
     *
     * <p> Call this before creating a new service endpoint.
     */
    public TraktV2 setAccessToken(String token) {
        mAccessToken = token;
        mRestAdapter = null;
        return this;
    }

    /**
     * Whether to return more detailed log output.
     *
     * <p> If enabled, sets the pre-built {@link retrofit.RestAdapter}'s log level to {@link
     * retrofit.RestAdapter.LogLevel#FULL}.
     *
     * <p> Call this before creating a new service endpoint.
     */
    public TraktV2 setIsDebug(boolean isDebug) {
        mIsDebug = isDebug;
        mRestAdapter = null;
        return this;
    }

    /**
     * If no instance exists yet (no service has been created or a setting was changed), builds a
     * new {@link RestAdapter} using the currently set authentication information and debug flag.
     * Otherwise returns the existing instance.
     */
    protected RestAdapter buildRestAdapter() {
        if (mRestAdapter == null) {
            RestAdapter.Builder builder = new RestAdapter.Builder().setEndpoint(API_URL);

            // Supply OAuth 2.0 access token
            builder.setRequestInterceptor(new RequestInterceptor() {
                @Override
                public void intercept(RequestFacade request) {
                    request.addQueryParam("access_token", mAccessToken);
                }
            });

            if (mIsDebug) {
                builder.setLogLevel(RestAdapter.LogLevel.FULL);
            }

            mRestAdapter = builder.build();
        }

        return mRestAdapter;
    }
}
