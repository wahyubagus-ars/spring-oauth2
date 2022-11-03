package ars.spring.oauth2.token;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class TokenStoreCustomizer extends TokenStoreHelper implements TokenStore, ResourceServerTokenServices {

    private int flushInterval = 1000;

    private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> userNameToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> clientIdToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, String> refreshTokenToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, String> accessTokenToRefreshTokenStore = new ConcurrentHashMap();
    private final AtomicInteger flushCounter = new AtomicInteger(0);
    private final DelayQueue<TokenExpiry> expiryQueue = new DelayQueue();
    private final ConcurrentHashMap<String, TokenExpiry> expiryMap = new ConcurrentHashMap();

    @SneakyThrows
    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
//        log.info("Value token {}", flushInterval);
////        if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
////            this.flush();
////            this.flushCounter.set(0);
////        }
//        String secondKey = getSecondKey(authentication);
//        String clientId = authentication.getOAuth2Request().getClientId();
//        //store authentication details to help client service getting the auth details
//
//        //sessionStorage.putCache("USER_SESSION", "OAUTH_ACCESS_TOKEN".concat(accessToken.getValue()), accessToken, sessionTimedOut);
        //sessionStorage.putCache("USER_SESSION", "OAUTH_AUTHENTICATION".concat(token.getValue()), authentication, sessionTimedOut);
//        //sessionStorage.putCache("USER_SESSION", "OAUTH_ACCESS_TOKEN".concat(this.authenticationKeyGenerator.extractKey(authentication).concat(secondKey)), accessToken, sessionTimedOut);
//
//        if (!authentication.isClientOnly()) {
//            //this.addToCollection(getApprovalKey(authentication), accessToken, sessionTimedOut);
//        }
//
//        //this.addToCollection(getApprovalKey(clientId, secondKey), accessToken, sessionTimedOut);
//
////        if (accessToken.getExpiration() != null) {
////            var expiry = new TokenExpiry(accessToken.getValue(), accessToken.getExpiration());
////
////        }
//
//        if (accessToken.getRefreshToken() != null && accessToken.getRefreshToken().getValue() != null) {
//
//        }

        if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
            this.flush();
            this.flushCounter.set(0);
        }

        this.accessTokenStore.put(token.getValue(), token);
        this.authenticationStore.put(token.getValue(), authentication);
        this.authenticationToAccessTokenStore.put(this.authenticationKeyGenerator.extractKey(authentication), token);
        if (!authentication.isClientOnly()) {
            this.addToCollection(this.userNameToAccessTokenStore, this.getApprovalKey(authentication), token);
        }

        this.addToCollection(this.clientIdToAccessTokenStore, authentication.getOAuth2Request().getClientId(), token);
        if (token.getExpiration() != null) {
            TokenExpiry expiry = new TokenExpiry(token.getValue(), token.getExpiration());
            this.expiryQueue.remove(this.expiryMap.put(token.getValue(), expiry));
            this.expiryQueue.put(expiry);
        }

        if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
            this.refreshTokenToAccessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
            this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
        }
    }

    @Override
    public OAuth2AccessToken readAccessToken(String s) {
        return new DefaultOAuth2AccessToken(s);
    }

//    @Override
//    public OAuth2AccessToken readAccessToken(String tokenValue) {
//        return (OAuth2AccessToken) sessionStorage.getCache("USER_SESSION", "OAUTH_ACCESS_TOKEN".concat(tokenValue));
//    }

    @Override
    public void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {

    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken, OAuth2Authentication oAuth2Authentication) {

    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String s) {
        return null;
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        return null;
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {

    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {

    }

    @Override
    public OAuth2Authentication loadAuthentication(String tokenValue) throws AuthenticationException, InvalidTokenException {
        OAuth2AccessToken accessToken = this.readAccessToken(tokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access tokenlala: " + tokenValue);
        } else if (accessToken.isExpired()) {
            this.removeAccessToken(accessToken);
            throw new InvalidTokenException("Access token expired: " + tokenValue);
        }

        OAuth2Authentication result = this.readAuthentication(accessToken);
        log.info("result token {}: ", result);
        if (result == null) {
            // in case of race condition
            throw new InvalidTokenException("Invalid access tokenlalal23423: " + tokenValue + "result: " + result);
        }
        return result;
    }

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken oAuth2AccessToken) {
        return this.readAuthentication(oAuth2AccessToken.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String s) {
        // return (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        return (OAuth2Authentication)this.authenticationStore.get(s);
    }

//    @Override
//    public OAuth2Authentication readAuthentication(String token) {
//        return (OAuth2Authentication) sessionStorage.getCache("USER_SESSION", "OAUTH_AUTHENTICATION".concat(token));
//    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication oAuth2Authentication) {
        return null;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String s, String s1) {
        return null;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String s) {
        return null;
    }
}
