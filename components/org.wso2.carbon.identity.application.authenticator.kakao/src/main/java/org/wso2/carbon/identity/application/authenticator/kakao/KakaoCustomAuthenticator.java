/*******************************************************************************
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 ******************************************************************************/

package org.wso2.carbon.identity.application.authenticator.kakao;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.MisconfigurationException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.AUTHENTICATOR_I18N_KEY;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.KAKAO_AUTH_URL;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.KAKAO_OAUTH2_STATE_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.REDIRECT_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID_PARAM;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ID_TOKEN_PARAM;

/***
 * Kakao Custom Authenticator is an outbound authenticator implementation for social login provider named Kakao
 * This extends Oauth Generic Authenticator implementation
 */
public class KakaoCustomAuthenticator extends Oauth2GenericAuthenticator {

    private static final long serialVersionUID = 6614257960044886319L;

    /**
     * Check whether the request can be handled by the authenticator.
     *
     * @param request The http servlet request
     * @return true if the request can be handled by the authenticator.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isNativeSDKBasedFederationCall(request) || super.canHandle(request);
    }

    @Override
    public String getFriendlyName() {

        return KakaoCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return KakaoCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return KakaoCustomAuthenticatorConstants.KAKAO_TOKEN_URL;
    }

    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return KAKAO_AUTH_URL;
    }

    @Override
    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return KakaoCustomAuthenticatorConstants.KAKAO_INFO_URL;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback url");
        configProperties.add(callbackUrl);

        return configProperties;
    }

    /**
     * Check whether the authentication is based on API.
     *
     * @return true since API based authentication is supported.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * Get the i18n key defined to represent the authenticator name.
     *
     * @return the 118n key.
     */
    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_I18N_KEY;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     * If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     * an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        if (context.getExternalIdP() != null) {
            authenticatorData.setIdp(context.getExternalIdP().getIdPName());
        }

        List<String> requiredParameterList = new ArrayList<>();
        if (isTrustedTokenIssuer(context)) {
            requiredParameterList.add(ACCESS_TOKEN_PARAM);
            requiredParameterList.add(ID_TOKEN_PARAM);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, true));
        } else {
            requiredParameterList.add(OAUTH2_GRANT_TYPE_CODE);
            requiredParameterList.add(OAUTH2_PARAM_STATE);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, false));
        }
        authenticatorData.setRequiredParams(requiredParameterList);
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE));
        }

        return Optional.of(authenticatorData);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        super.initiateAuthenticationRequest(request, response, context);
        String clientId = context.getAuthenticatorProperties().get(CLIENT_ID);
        String state = context.getContextIdentifier() + KAKAO_OAUTH2_STATE_SUFFIX;
        String redirectUri = context.getAuthenticatorProperties().get(CALLBACK_URL);
        context.setProperty(OAUTH2_PARAM_STATE, state);
        StringBuilder redirectUrl = new StringBuilder(KAKAO_AUTH_URL)
                .append("?response_type=code")
                .append("&client_id=").append(clientId)
                .append("&redirect_uri=").append(redirectUri)
                .append("&state=").append(state);
        context.setProperty(REDIRECT_URL, redirectUrl.toString());
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String token;
            if (isNativeSDKBasedFederationCall(request)) {
                token = request.getParameter(ACCESS_TOKEN_PARAM);
                String idToken = request.getParameter(ID_TOKEN_PARAM);
                if (StringUtils.isNotBlank(idToken)) {
                    validateJWTToken(context, idToken);
                }
            } else {
                String clientId = authenticatorProperties.get(CLIENT_ID);
                String clientSecret = authenticatorProperties.get(CLIENT_SECRET);
                String redirectUri = authenticatorProperties.get(CALLBACK_URL);
                Boolean basicAuthEnabled = Boolean.parseBoolean(authenticatorProperties
                        .get(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED));
                String code = getAuthorizationCode(request);
                String tokenEP = getTokenEndpoint(authenticatorProperties);
                token = getToken(tokenEP, clientId, clientSecret, code, redirectUri, basicAuthEnabled);
            }

            Boolean selfContainedTokenEnabled = Boolean.parseBoolean(authenticatorProperties
                    .get(Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED));
            String userInfo = getUserInfo(selfContainedTokenEnabled, token, authenticatorProperties);
            buildClaims(context, userInfo);
        } catch (ApplicationAuthenticatorException | MisconfigurationException e) {
            String errorMessage = "Error while processing authentication response.";
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private boolean isTrustedTokenIssuer(AuthenticationContext context) {

        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        if (externalIdPConfig == null) {
            return false;
        }

        IdentityProvider externalIdentityProvider = externalIdPConfig.getIdentityProvider();
        if (externalIdentityProvider == null) {
            return false;
        }

        IdentityProviderProperty[] identityProviderProperties = externalIdentityProvider.getIdpProperties();
        for (IdentityProviderProperty identityProviderProperty : identityProviderProperties) {
            if (IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER.equals(identityProviderProperty.getName())) {
                return Boolean.parseBoolean(identityProviderProperty.getValue());
            }
        }

        return false;
    }

    private boolean isNativeSDKBasedFederationCall(HttpServletRequest request) {

        return request.getParameter(ACCESS_TOKEN_PARAM) != null && request.getParameter(ID_TOKEN_PARAM) != null;
    }

    private AdditionalData getAdditionalData(AuthenticationContext context, boolean isNativeSDKBasedFederationCall) {

        AdditionalData additionalData = new AdditionalData();
        Map<String, String> additionalAuthenticationParams = new HashMap<>();
        if (isNativeSDKBasedFederationCall) {
            additionalAuthenticationParams.put(CLIENT_ID_PARAM,
                    context.getAuthenticatorProperties().get(CLIENT_ID));
        } else {
            additionalAuthenticationParams.put(REDIRECT_URL, context.getProperty(REDIRECT_URL).toString());
            additionalAuthenticationParams.put(OAUTH2_PARAM_STATE, context.getProperty(OAUTH2_PARAM_STATE).toString());
        }
        additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        return additionalData;
    }

    private void validateJWTToken(AuthenticationContext context, String idToken) throws AuthenticationFailedException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            validateAudience(context, claimsSet.getAudience());
            OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
            String tenantDomain = context.getTenantDomain();
            String idpIdentifier = OIDCTokenValidationUtil.getIssuer(claimsSet);
            IdentityProvider identityProvider = getIdentityProvider(idpIdentifier, tenantDomain);

            if (identityProvider == null) {
                String msg = String.format(
                        KakaoCustomAuthenticatorConstants.ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER.getCode(), idpIdentifier);
                AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(
                        FrameworkConstants.AuthenticatorMessageType.ERROR,
                        KakaoCustomAuthenticatorConstants.ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER.getCode(),
                        msg,
                        null);
                setAuthenticatorMessageToContext(authenticatorMessage, context);
                throw new AuthenticationFailedException(msg);
            }

            OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
        } catch (ParseException | JOSEException | IdentityProviderManagementException | IdentityOAuth2Exception e) {
            setAuthenticatorMessageToContext(
                    KakaoCustomAuthenticatorConstants.ErrorMessages.JWT_TOKEN_VALIDATION_FAILED, context);
            throw new AuthenticationFailedException(KakaoCustomAuthenticatorConstants.ErrorMessages.
                    JWT_TOKEN_VALIDATION_FAILED.getMessage(), e);
        }
    }

    private void validateAudience(AuthenticationContext context, List<String> audience)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(CLIENT_ID);
        if (audience == null || !audience.contains(clientId)) {
            setAuthenticatorMessageToContext(KakaoCustomAuthenticatorConstants.ErrorMessages
                    .ID_TOKEN_AUD_VALIDATION_FAILED, context);
            throw new AuthenticationFailedException(
                    KakaoCustomAuthenticatorConstants.ErrorMessages.ID_TOKEN_AUD_VALIDATION_FAILED.getMessage());
        }
    }

    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws IdentityProviderManagementException {

        IdentityProvider identityProvider;
        identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

        if (identityProvider == null) {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
        }

        return identityProvider;
    }

    private static void setAuthenticatorMessageToContext(AuthenticatorMessage message,
                                                         AuthenticationContext context) {

        context.setProperty(AUTHENTICATOR_MESSAGE, message);
    }

    private static void setAuthenticatorMessageToContext(KakaoCustomAuthenticatorConstants.ErrorMessages errorMessage,
                                                         AuthenticationContext context) {

        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.ERROR, errorMessage.getCode(), errorMessage.getMessage(), null);
        context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }
}

