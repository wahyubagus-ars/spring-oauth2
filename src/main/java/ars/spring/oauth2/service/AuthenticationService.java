package ars.spring.oauth2.service;

import ars.spring.oauth2.domain.dao.Client;
import ars.spring.oauth2.domain.dao.Role;
import ars.spring.oauth2.domain.dao.User;
import ars.spring.oauth2.domain.dto.AuthRequest;
import ars.spring.oauth2.domain.dto.AuthResponse;
import ars.spring.oauth2.repository.UserRepository;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
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
import java.util.function.Function;
import java.util.stream.Collectors;

import static ars.spring.oauth2.constant.AppConstant.*;
import static ars.spring.oauth2.constant.Role.ADMIN;
import static ars.spring.oauth2.constant.Role.USER;

@Service
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenEndpoint tokenEndpoint;

    @SneakyThrows
    public ResponseEntity<AuthResponse> authenticate(AuthRequest request,HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Optional<User> user = userRepository.findFirstByUsername(request.getUsername());

        if (user.isEmpty()) return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        OAuth2AccessToken oAuth2AccessToken = this.getAccessToken(user.get(), servletRequest);
        if (Objects.isNull(oAuth2AccessToken)) {
            return new ResponseEntity<>(AuthResponse.builder()
                    .status("FAIL")
                    .build(), HttpStatus.UNAUTHORIZED);
        }
        servletResponse.addHeader("token_access", oAuth2AccessToken.getValue());

        return new ResponseEntity<>(AuthResponse.builder()
                .username(user.get().getUsername())
                .status("SUCCESS")
                .build(), HttpStatus.OK);
    }

    public ResponseEntity<AuthResponse> getProfile(HttpServletRequest servletRequest) {
        var oAuth2Authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        String username = oAuth2Authentication.getOAuth2Request().getRequestParameters().get(USER_ID);
        return new ResponseEntity<>(AuthResponse.builder()
                .username(username)
                .status("SUCCESS")
                .build(), HttpStatus.OK);
    }

    public OAuth2AccessToken getAccessToken(User user, HttpServletRequest servletRequest) throws HttpRequestMethodNotSupportedException {

        HashMap<String, String> parameters = new HashMap<>();
        Collection<GrantedAuthority> authorityCollection = new ConcurrentLinkedDeque<>();
        org.springframework.security.core.userdetails.User userPrincipal;
        UsernamePasswordAuthenticationToken principal;
        ResponseEntity<OAuth2AccessToken> accessToken;

        Map<String, Client> userClient = user.getClients()
                .stream()
                .collect(Collectors.toMap(data -> data.getClientSecret().concat(data.getIdClient()), Function.identity()));

        Client client = userClient.get(servletRequest.getHeader(SERV_CLIENT_ID).concat(servletRequest.getHeader(SERV_CLIENT_SECRET)));
        if (Objects.isNull(client)) {
            return null;
        }

        parameters.put(CLIENT_ID, client.getIdClient());
        parameters.put(CLIENT_SECRET, client.getClientSecret());
        parameters.put(GRANT_TYPE, "client_credentials");
        parameters.put(USER_ID, user.getUsername());

        userPrincipal = new org.springframework.security.core.userdetails.User(client.getIdClient(), client.getClientSecret(), true, true, true, true, authorityCollection);
        principal = new UsernamePasswordAuthenticationToken(userPrincipal, client.getClientSecret(), authorityCollection);
        accessToken = tokenEndpoint.postAccessToken(principal, parameters);

        return accessToken.getBody();
    }
}
