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

package org.wso2.carbon.identity.application.authenticator.kakao.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.kakao.KakaoCustomAuthenticator;

import java.util.Hashtable;

@Component(name = "KakaoServiceComponent", immediate = true)
public class KakaoServiceComponent {

    private static final Log logger = LogFactory.getLog(KakaoServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            KakaoCustomAuthenticator kakaoAuthenticator = new KakaoCustomAuthenticator();
            Hashtable<String, String> props = new Hashtable<>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), kakaoAuthenticator,
                    props);
            if (logger.isDebugEnabled()) {
                logger.debug("----Kakao Authenticator bundle is activated----");
            }

        } catch (Throwable e) {
            logger.error("----Error while activating Kakao authenticator----", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (logger.isDebugEnabled()) {
            logger.debug("----Kakao Authenticator bundle is deactivated----");
        }
    }

}