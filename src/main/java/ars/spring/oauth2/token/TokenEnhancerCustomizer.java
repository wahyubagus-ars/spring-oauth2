package ars.spring.oauth2.token;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TokenEnhancerCustomizer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        var defaultOAuth2AccessToken = new DefaultOAuth2AccessToken(oAuth2AccessToken);
        defaultOAuth2AccessToken.setValue(DigestUtils.sha256Hex(defaultOAuth2AccessToken.getValue()));
        return defaultOAuth2AccessToken;
    }
}
