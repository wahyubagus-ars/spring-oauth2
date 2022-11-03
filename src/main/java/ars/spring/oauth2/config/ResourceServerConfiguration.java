package ars.spring.oauth2.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

@EnableResourceServer
@Configuration
@Slf4j
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Value("${management.server.port:9090}")
    private int managementPort;

    @Value(value = "${oauth2.session.client.id}")
    private String clientId;
    @Value(value = "${oauth2.session.secret}")
    private String secret;

    public ResourceServerConfiguration() {
        super();
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/authentication/login").permitAll()
                .antMatchers("/admin/**").hasAuthority("ADMIN")
                .antMatchers("/user/**").hasAuthority("USER")
                .requestMatchers(checkPort(managementPort)).permitAll()
                .antMatchers("/**").authenticated();

    }

    private RequestMatcher checkPort(final int port) {
        return (HttpServletRequest request) -> port == request.getLocalPort();
    }
}
