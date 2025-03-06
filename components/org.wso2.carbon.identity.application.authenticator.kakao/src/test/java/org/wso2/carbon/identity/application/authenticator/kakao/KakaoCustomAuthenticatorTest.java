/*
 *  Copyright (c) 2025, WSO2 LLC (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 LLC licenses this file to you under the Apache license,
 *  Version 2.0 (the "license"); you may not use this file except
 *  in compliance with the license.
 *  You may obtain a copy of the license at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.application.authenticator.kakao;

import org.mockito.Mockito;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.AUTHENTICATOR_I18N_KEY;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.KAKAO_AUTH_URL;
import static org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticatorConstants.REDIRECT_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Unit test cases for KakaoCustomAuthenticator.
 */
public class KakaoCustomAuthenticatorTest {

    final String TEST_REDIRECT_URL = "http://testkakaoredirect.com";
    final String TEST_STATE = "test_scope";
    final String TEST_CLIENT_ID = "testClientId";
    final String TEST_CLIENT_SECRET = "testClientSecret";
    final String TEST_AUTH_ENDPOINT = "http://testauth.com";

    @DataProvider(name = "canHandleDataProvider")
    public Object[][] canHandleDataProvider() {
        return new Object[][]{
                {null, null, false},
                {"accessToken", null, false},
                {null, "idToken", false},
                {"accessToken", "idToken", true},
        };
    }

    @Test(dataProvider = "canHandleDataProvider")
    public void testCanHandleNativeSDKBasedFederationCall(String accessToken, String idToken, Boolean expectedResult) {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getParameter(OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM)).thenReturn(accessToken);
        when(request.getParameter(OIDCAuthenticatorConstants.ID_TOKEN_PARAM)).thenReturn(idToken);
        assertEquals(authenticator.canHandle(request), expectedResult, "Can handle is not as expected");
    }

    @Test
    public void testGetName() {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        assertEquals(authenticator.getName(), KakaoCustomAuthenticatorConstants.AUTHENTICATOR_NAME,
                "Authenticator name is not as expected");
    }

    @Test
    public void testGetAuthorizationServerEndpoint() {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        assertEquals(authenticator.getAuthorizationServerEndpoint(null),
                KakaoCustomAuthenticatorConstants.KAKAO_AUTH_URL, "Authorization server endpoint is not as expected");
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        assertTrue(authenticator.isAPIBasedAuthenticationSupported(), "API based authentication is not supported");
    }

    @Test
    public void testGetI18nKey() {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        assertEquals(authenticator.getI18nKey(), AUTHENTICATOR_I18N_KEY, "I18n key is not as expected");
    }

    @Test
    public void testGetAuthInitiationDataWhenTrustedTokenIssuer() {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        AuthenticationContext context = Mockito.mock(AuthenticationContext.class);
        ExternalIdPConfig externalIdPConfig = Mockito.mock(ExternalIdPConfig.class);
        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        IdentityProvider identityProvider = Mockito.mock(IdentityProvider.class);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        IdentityProviderProperty identityProviderProperty = Mockito.mock(IdentityProviderProperty.class);
        when(identityProvider.getIdpProperties()).thenReturn(new IdentityProviderProperty[]{identityProviderProperty});
        when(identityProviderProperty.getName()).thenReturn(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        when(identityProviderProperty.getValue()).thenReturn("true");

        Optional<AuthenticatorData> authInitiationData = authenticator.getAuthInitiationData(context);
        assertTrue(authInitiationData.isPresent(), "Auth initiation data is not present");
        assertTrue(authInitiationData.get().getRequiredParams().containsAll(Arrays.asList(
                OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM,
                OIDCAuthenticatorConstants.ID_TOKEN_PARAM)), "Required params are not as expected");
        assertEquals(authInitiationData.get().getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT, "Prompt type is not as expected");
    }

    @DataProvider(name = "ExternalIDPConfigDataProvider")
    public Object[][] externalIdentityProviderDataProvider() {

        AuthenticationContext contextWithExternalIDPNull = Mockito.mock(AuthenticationContext.class);
        when(contextWithExternalIDPNull.getExternalIdP()).thenReturn(null);

        AuthenticationContext contextWithExternalIDPConfigNull = Mockito.mock(AuthenticationContext.class);
        ExternalIdPConfig externalIdPConfigWithExternalIDPNull = Mockito.mock(ExternalIdPConfig.class);
        when(contextWithExternalIDPConfigNull.getExternalIdP()).thenReturn(externalIdPConfigWithExternalIDPNull);
        when(externalIdPConfigWithExternalIDPNull.getIdentityProvider()).thenReturn(null);

        AuthenticationContext contextWithIsTrustedTokenIssuerConfigFalse = Mockito.mock(AuthenticationContext.class);
        ExternalIdPConfig externalIdPConfigWithIsTrustedTokenIssuerConfigFalse = Mockito.mock(ExternalIdPConfig.class);
        when(contextWithIsTrustedTokenIssuerConfigFalse.getExternalIdP())
                .thenReturn(externalIdPConfigWithIsTrustedTokenIssuerConfigFalse);
        IdentityProvider identityProviderWithIsTrustedTokenIssuerConfigFalse = Mockito.mock(IdentityProvider.class);
        when(externalIdPConfigWithIsTrustedTokenIssuerConfigFalse.getIdentityProvider())
                .thenReturn(identityProviderWithIsTrustedTokenIssuerConfigFalse);
        IdentityProviderProperty identityProviderProperty = Mockito.mock(IdentityProviderProperty.class);
        when(identityProviderWithIsTrustedTokenIssuerConfigFalse.getIdpProperties())
                .thenReturn(new IdentityProviderProperty[]{identityProviderProperty});
        when(identityProviderProperty.getName()).thenReturn(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        when(identityProviderProperty.getValue()).thenReturn("false");

        return new Object[][]{
                {contextWithExternalIDPConfigNull},
                {contextWithExternalIDPNull},
                {contextWithIsTrustedTokenIssuerConfigFalse}
        };
    }
    
    @Test(dataProvider = "ExternalIDPConfigDataProvider")
    public void testGetAuthInitiationDataWhenNotTrustedTokenIssuer(AuthenticationContext context) {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        when(context.getProperty(REDIRECT_URL)).thenReturn(TEST_REDIRECT_URL);
        when(context.getProperty(OAUTH2_PARAM_STATE)).thenReturn(TEST_STATE);

        Optional<AuthenticatorData> authInitiationData = authenticator.getAuthInitiationData(context);
        assertTrue(authInitiationData.isPresent(), "Auth initiation data is not present");
        assertTrue(authInitiationData.get().getRequiredParams().containsAll(Arrays.asList(OAUTH2_GRANT_TYPE_CODE,
                OAUTH2_PARAM_STATE)), "Required params are not as expected");
        assertEquals(authInitiationData.get().getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT, "Prompt type is not as expected");
    }

    @Test
    public void testInitiateAuthenticationRequest() throws AuthenticationFailedException {

        KakaoCustomAuthenticator authenticator = new KakaoCustomAuthenticator();
        AuthenticationContext context = new AuthenticationContext();
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("ClientId", TEST_CLIENT_ID);
        authenticatorProperties.put("ClientSecret", TEST_CLIENT_SECRET);
        authenticatorProperties.put("CallbackUrl", TEST_REDIRECT_URL);
        authenticatorProperties.put("AuthEndpoint", TEST_AUTH_ENDPOINT);
        context.setAuthenticatorProperties(authenticatorProperties);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        context.setProperty(REDIRECT_URL, TEST_REDIRECT_URL);
        context.setProperty(OAUTH2_PARAM_STATE, TEST_STATE);

        authenticator.initiateAuthenticationRequest(request, response, context);
        StringBuilder partialExpectedRedirectUrlWithoutState = new StringBuilder(KAKAO_AUTH_URL)
                .append("?response_type=code")
                .append("&client_id=").append(TEST_CLIENT_ID)
                .append("&redirect_uri=").append(TEST_REDIRECT_URL);
        assertTrue(context.getProperty(REDIRECT_URL) != null && ((String)context.getProperty(REDIRECT_URL))
                .contains(partialExpectedRedirectUrlWithoutState.toString()), "Redirect URL is not as expected");
    }
}
