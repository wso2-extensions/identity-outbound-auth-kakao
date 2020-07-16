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

import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/***
 * Kakao Custom Authenticator is an outbound authenticator implementation for social login provider named Kakao
 * This extends Oauth Generic Authenticator implementation
 */
public class KakaoCustomAuthenticator extends Oauth2GenericAuthenticator {

    private static final long serialVersionUID = 6614257960044886319L;

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

        return KakaoCustomAuthenticatorConstants.KAKAO_AUTH_URL;
    }

    @Override
    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return KakaoCustomAuthenticatorConstants.KAKAO_INFO_URL;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(KakaoCustomAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(KakaoCustomAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(KakaoCustomAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback url");
        configProperties.add(callbackUrl);

        return configProperties;
    }
}

