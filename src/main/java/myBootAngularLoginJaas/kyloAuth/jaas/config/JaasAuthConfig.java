package myBootAngularLoginJaas.kyloAuth.jaas.config;


/*-
* #%L
* thinkbig-security-auth
* %%
* Copyright (C) 2017 ThinkBig Analytics
* %%
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
* #L%
*/

import myBootAngularLoginJaas.kyloAuth.DefaultPrincipalAuthorityGranter;
import myBootAngularLoginJaas.kyloAuth.GroupPrincipalAuthorityGranter;
import myBootAngularLoginJaas.kyloAuth.UserPrincipalAuthorityGranter;
import myBootAngularLoginJaas.kyloAuth.jaas.DefaultKyloJaasAuthenticationProvider;
import myBootAngularLoginJaas.kyloAuth.jaas.LoginConfiguration;
import myBootAngularLoginJaas.kyloAuth.jaas.LoginConfigurationBuilder;
import myBootAngularLoginJaas.kyloAuth.jaas.UsernameJaasAuthenticationProvider;
import myBootAngularLoginJaas.kyloAuth.jaas.http.JaasHttpCallbackHandlerFilter;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.jaas.AbstractJaasAuthenticationProvider;
import org.springframework.security.authentication.jaas.AuthorityGranter;
import org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider;
import org.springframework.security.authentication.jaas.JaasAuthenticationCallbackHandler;
import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.inject.Named;
import javax.security.auth.login.AppConfigurationEntry;

/**
*
*/
@Configuration
public class JaasAuthConfig {

   public static final String JAAS_UI = "UI";
   public static final String JAAS_UI_TOKEN = "UI-Token";
   public static final String JAAS_SERVICES = "Services";
   public static final String JAAS_SERVICES_TOKEN = "Services-Token";

   public static final String SERVICES_AUTH_PROVIDER = "servicesAuthenticationProvider";
   public static final String SERVICES_TOKEN_AUTH_PROVIDER = "servicesTokenAuthenticationProvider";
   public static final String UI_AUTH_PROVIDER = "uiAuthenticationProvider";
   public static final String UI_TOKEN_AUTH_PROVIDER = "uiTokenAuthenticationProvider";

   public static final int DEFAULT_GRANTER_ORDER = Integer.MAX_VALUE - 100;

   private static final JaasAuthenticationCallbackHandler[] CALLBACK_HANDLERS 
       = new JaasAuthenticationCallbackHandler[] { new JaasAuthenticationNameCallbackHandler(), 
                                                   new JaasAuthenticationPasswordCallbackHandler(),
                                                   JaasHttpCallbackHandlerFilter.CALLBACK_HANDLER
                                                 };

   @Bean(name = UI_AUTH_PROVIDER)
   public AbstractJaasAuthenticationProvider uiAuthenticationProvider(@Named("jaasConfiguration") javax.security.auth.login.Configuration config,
                                                                      List<AuthorityGranter> authorityGranters) {
       DefaultJaasAuthenticationProvider provider = new DefaultKyloJaasAuthenticationProvider();
       provider.setCallbackHandlers(CALLBACK_HANDLERS);
       provider.setConfiguration(config);
       provider.setAuthorityGranters(authorityGranters.toArray(new AuthorityGranter[authorityGranters.size()]));
       provider.setLoginContextName(JAAS_UI);
       return provider;
   }

   @Bean(name = SERVICES_AUTH_PROVIDER)
   public AbstractJaasAuthenticationProvider servicesAuthenticationProvider(@Named("jaasConfiguration") javax.security.auth.login.Configuration config,
                                                                            List<AuthorityGranter> authorityGranters) {
       DefaultJaasAuthenticationProvider provider = new DefaultKyloJaasAuthenticationProvider();
       provider.setCallbackHandlers(CALLBACK_HANDLERS);
       provider.setConfiguration(config);
       provider.setAuthorityGranters(authorityGranters.toArray(new AuthorityGranter[authorityGranters.size()]));
       provider.setLoginContextName(JAAS_SERVICES);
       return provider;
   }

   @Bean(name = UI_TOKEN_AUTH_PROVIDER)
   public AbstractJaasAuthenticationProvider uiTokenAuthenticationProvider(@Named("jaasConfiguration") javax.security.auth.login.Configuration config,
                                                                           List<AuthorityGranter> authorityGranters) {
       UsernameJaasAuthenticationProvider provider = new UsernameJaasAuthenticationProvider();
       provider.setCallbackHandlers(CALLBACK_HANDLERS);
       provider.setConfiguration(config);
       provider.setAuthorityGranters(authorityGranters.toArray(new AuthorityGranter[authorityGranters.size()]));
       provider.setLoginContextName(JAAS_UI_TOKEN);
       return provider;
   }

   @Bean(name = SERVICES_TOKEN_AUTH_PROVIDER)
   public AbstractJaasAuthenticationProvider servicesTokenAuthenticationProvider(@Named("jaasConfiguration") javax.security.auth.login.Configuration config,
                                                                                 List<AuthorityGranter> authorityGranters) {
       UsernameJaasAuthenticationProvider provider = new UsernameJaasAuthenticationProvider();
       provider.setCallbackHandlers(CALLBACK_HANDLERS);
       provider.setConfiguration(config);
       provider.setAuthorityGranters(authorityGranters.toArray(new AuthorityGranter[authorityGranters.size()]));
       provider.setLoginContextName(JAAS_SERVICES_TOKEN);
       return provider;
   }

   @Bean(name = "jaasConfiguration")
   public javax.security.auth.login.Configuration jaasConfiguration(Optional<List<LoginConfiguration>> loginModuleEntries) {
       // Generally the entries will be null only in situations like unit/integration tests.
       if (loginModuleEntries.isPresent()) {
           List<LoginConfiguration> sorted = new ArrayList<>(loginModuleEntries.get());
           sorted.sort(new AnnotationAwareOrderComparator());
           
           Map<String, AppConfigurationEntry[]> merged = sorted.stream()
                           .map(c -> c.getAllApplicationEntries().entrySet())
                           .flatMap(s -> s.stream())
                           .collect(Collectors.toMap(e -> e.getKey(),
                                                     e -> e.getValue(),
                                                     ArrayUtils::addAll));
           return new InMemoryConfiguration(merged);
       } else {
           return new InMemoryConfiguration(Collections.emptyMap());
       }
   }

   @Bean(name = "groupPrincipalAuthorityGranter")
   @Order(DEFAULT_GRANTER_ORDER - 100)
   public AuthorityGranter groupPrincipalAuthorityGranter() {
       return new GroupPrincipalAuthorityGranter();
   }

   @Bean(name = "userPrincipalAuthorityGranter")
   @Order(DEFAULT_GRANTER_ORDER - 100)
   public AuthorityGranter userPrincipalAuthorityGranter() {
       return new UserPrincipalAuthorityGranter();
   }

   @Bean(name = "defaultAuthorityGranter")
   @Order(DEFAULT_GRANTER_ORDER)
   public AuthorityGranter defaultAuthorityGranter() {
       return new DefaultPrincipalAuthorityGranter();
   }

   @Bean
   @Scope("prototype")
   public LoginConfigurationBuilder loginConfigurationBuilder() {
       return new DefaultLoginConfigurationBuilder();
   }
}
