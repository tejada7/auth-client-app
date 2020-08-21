package com.ftm.oauthclient.config;

import com.ftm.oauthclient.custom.CustomAuthorizationRequestResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final Environment env;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository, Environment env) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.env = env;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/img/**")
                .permitAll()
                .anyRequest()
                .fullyAuthenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .authorizationRequestResolver(new CustomAuthorizationRequestResolver(
                        clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                        /*"http://localhost:8080/oauth/authorize"*/
                ));

//        if (Boolean.valueOf(env.getProperty("okta.oauth2.pkce-always"))) {
//            http
//                    .oauth2Login()
//                    .authorizationEndpoint()
//                    .authorizationRequestResolver(new CustomAuthorizationRequestResolver(
//                            clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
//                    ));
//        }
    }
}