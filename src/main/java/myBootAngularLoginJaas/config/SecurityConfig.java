package myBootAngularLoginJaas.config;

import javax.inject.Inject;
import javax.inject.Named;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.jaas.AbstractJaasAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import myBootAngularLoginJaas.kyloAuth.config.SessionDestroyEventLogoutHandler;
import myBootAngularLoginJaas.kyloAuth.jaas.config.JaasAuthConfig;
import myBootAngularLoginJaas.security.jwt.AuthEntryPointJwt;
import myBootAngularLoginJaas.security.jwt.AuthTokenFilter;
import myBootAngularLoginJaas.security.services.UserDetailsServiceImpl;

//@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(
		// securedEnabled = true,
		// jsr250Enabled = true,
		prePostEnabled = true)
public class SecurityConfig extends BaseWebSecurityConfigurer {
	
	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
	
    /**
     * Defining these beens in an embedded configuration to ensure they are all constructed
     * before being used by the logout filter.
     */
    @Configuration
    
    static class UiHandlersConfig {
        @Inject
        @Named(JaasAuthConfig.SERVICES_AUTH_PROVIDER)
        private AbstractJaasAuthenticationProvider authenticationProvider;

        @Bean(name="jaasLogoutHandler-ui")
        public LogoutHandler jassUiLogoutHandler() {
            // Sends a SessionDestroyEvent directly (not through a publisher) to the auth provider.
            return new SessionDestroyEventLogoutHandler(authenticationProvider);
        }
        
        @Bean(name="defaultUrlLogoutSuccessHandler-ui")
        public LogoutSuccessHandler defaultUrlLogoutSuccessHandler() {
            SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
            handler.setTargetUrlParameter("redirect");
            handler.setDefaultTargetUrl(UI_LOGOUT_REDIRECT_URL);
            return handler;
        }
    }

	
	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;

	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(uiAuthenticationProvider);
    }
   

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		logger.info("*********LOGGER.INFO************");
		http.cors().and().csrf().disable()
			.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
			.authorizeRequests().antMatchers( "/api/auth/**").permitAll()
			.antMatchers("/api/test/**").permitAll()
			.antMatchers("/api/rest/**").permitAll()
			.anyRequest().authenticated();
		http.addFilterBefore(jaasFilter(), BasicAuthenticationFilter.class);

		//http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
}
