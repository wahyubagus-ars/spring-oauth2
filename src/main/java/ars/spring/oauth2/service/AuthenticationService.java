package ars.spring.oauth2.service;

import ars.spring.oauth2.domain.dao.Role;
import ars.spring.oauth2.domain.dao.User;
import ars.spring.oauth2.domain.dto.AuthRequest;
import ars.spring.oauth2.domain.dto.AuthResponse;
import ars.spring.oauth2.repository.UserRepository;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.stereotype.Service;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

@Service
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenEndpoint tokenEndpoint;

    @Value(value = "${oauth2.session.client.id}")
    private String clientId;
    @Value(value = "${oauth2.session.secret}")
    private String secret;

    @Value(value = "${oauth2.session.client.id2}")
    private String clientId2;

    @Value(value = "${oauth2.session.secret2}")
    private String secret2;

    public static final String USERNAME = "user_id";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String GRANT_TYPE = "grant_type";
    public static final String USER = "user";
    public static final String ADMIN = "admin";

    @SneakyThrows
    public ResponseEntity authenticate(AuthRequest request, HttpServletResponse servletResponse) {
        Optional<User> user = userRepository.findFirstByUsername(request.getUsername());

        if (user.isEmpty()) return new ResponseEntity(HttpStatus.NOT_FOUND);

        OAuth2AccessToken oAuth2AccessToken = this.getAccessToken(user.get());

        servletResponse.addHeader("token_access", oAuth2AccessToken.getValue());
        return new ResponseEntity(AuthResponse.builder()
                .username(user.get().getUsername())
                .status("SUCCESS")
                .build(), HttpStatus.OK);
    }

    public ResponseEntity getProfile(HttpServletRequest servletRequest) {
        var oAuth2Authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        String username = oAuth2Authentication.getOAuth2Request().getRequestParameters().get(USERNAME);
        return new ResponseEntity(AuthResponse.builder()
                .username(username)
                .status("SUCCESS")
                .build(), HttpStatus.OK);
    }

    public OAuth2AccessToken getAccessToken(User user) throws HttpRequestMethodNotSupportedException {

        HashMap<String, String> parameters = new HashMap<>();
        Collection<GrantedAuthority> authorityCollection = new ConcurrentLinkedDeque<>();
//        authorityCollection.add(new SimpleGrantedAuthority("ADMIN"));
        org.springframework.security.core.userdetails.User userPrincipal;
        UsernamePasswordAuthenticationToken principal;
        ResponseEntity<OAuth2AccessToken> accessToken;
        String clientId = null;
        String clientSecret = null;

        List<String> listRoles = user.getRoles().stream()
                .map(Role::getRole)
                .collect(Collectors.toList());

        if (listRoles.contains(ADMIN)) {
            clientId = this.clientId2;
            clientSecret = this.secret2;
        } else if (listRoles.contains(USER)) {
            clientId = this.clientId;
            clientSecret = this.secret;
        }

        parameters.put(CLIENT_ID, clientId);
        parameters.put(CLIENT_SECRET, clientSecret);
        parameters.put(GRANT_TYPE, "client_credentials");
        parameters.put(USERNAME, user.getUsername());

        userPrincipal = new org.springframework.security.core.userdetails.User(clientId, clientSecret, true, true, true, true, authorityCollection);
        principal = new UsernamePasswordAuthenticationToken(userPrincipal, clientSecret, authorityCollection);
        accessToken = tokenEndpoint.postAccessToken(principal, parameters);

        return accessToken.getBody();
    }
}
