package ars.spring.oauth2.config;

import ars.spring.oauth2.domain.dao.Client;
import ars.spring.oauth2.domain.dao.ClientDetails;
import ars.spring.oauth2.repository.ClientRepository;
import ars.spring.oauth2.token.TokenEnhancerCustomizer;
import ars.spring.oauth2.token.TokenStoreDefault;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableAuthorizationServer
@Slf4j
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private WebResponseExceptionTranslator loggingExceptionTranslator;

    @Autowired
    private TokenEnhancerCustomizer tokenEnhancerCustomizer;

    @Autowired
    private ClientRepository clientRepository;

    @Value(value = "${oauth2.session.life:600}")
    private int sessionTimedOut;

    @Value(value = "${oauth2.session.refresh:600}")
    private int sessionRefresh;


    private static final String READ = "read";
    private static final String WRITE = "write";
    private static final String TRUST = "trust";


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                .passwordEncoder(passwordEncoder())
                .allowFormAuthenticationForClients()
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        List<Client> clientList = clientRepository.findAll();
        log.info("Clients:: {}", clientList);
        clients.inMemory();

        for (Client client : clientList) {
            List<String> authorities = client.getDetails()
                    .stream()
                    .map(ClientDetails::getRole)
                    .collect(Collectors.toList());

            clients.and()
                    .withClient(client.getIdClient())
                    .authorizedGrantTypes("client_credentials")
                    .scopes(READ, WRITE, TRUST)
                    .authorities(authorities.toArray(new String[]{}))
                    .secret(client.getClientSecret())
                    .accessTokenValiditySeconds(sessionTimedOut)
                    .refreshTokenValiditySeconds(sessionRefresh);
        }
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                .authenticationManager(authenticationManager)
                .exceptionTranslator(loggingExceptionTranslator)
                .tokenStore(tokenStoreDefault())
                .tokenEnhancer(tokenEnhancerCustomizer);
    }

    @Bean
    @Primary
    public TokenStoreDefault tokenStoreDefault() {
        return new TokenStoreDefault();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public DefaultTokenServices tokenServices() {
        var defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStoreDefault());
        return defaultTokenServices;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
