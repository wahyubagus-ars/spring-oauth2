package ars.spring.oauth2.controller;

import ars.spring.oauth2.domain.dto.AuthRequest;
import ars.spring.oauth2.domain.dto.AuthResponse;
import ars.spring.oauth2.service.AuthenticationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RestController
public class AuthController {
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping(value = "/authentication/login", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthResponse> getData(@RequestBody AuthRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        return authenticationService.authenticate(request, servletRequest, servletResponse);
    }

    @GetMapping(value = "/admin/get-profile", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthResponse> getAdminProfile(HttpServletRequest servletRequest) throws HttpRequestMethodNotSupportedException {
        return authenticationService.getProfile(servletRequest);
    }

    @GetMapping(value = "/user/get-profile", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthResponse> getUserProfile(HttpServletRequest servletRequest) throws HttpRequestMethodNotSupportedException {
        return authenticationService.getProfile(servletRequest);
    }
}
