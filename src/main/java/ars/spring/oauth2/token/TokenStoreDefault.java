package ars.spring.oauth2.token;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class TokenStoreDefault implements TokenStore, ResourceServerTokenServices {

    private ClientDetailsService clientDetailsService;

    private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> userNameToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> clientIdToAccessTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, OAuth2RefreshToken> refreshTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, String> accessTokenToRefreshTokenStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, OAuth2Authentication> refreshTokenAuthenticationStore = new ConcurrentHashMap();
    private final ConcurrentHashMap<String, String> refreshTokenToAccessTokenStore = new ConcurrentHashMap();
    private final DelayQueue<TokenExpiry> expiryQueue = new DelayQueue();
    private final ConcurrentHashMap<String, TokenExpiry> expiryMap = new ConcurrentHashMap();
    private int flushInterval = 1000;
    private AtomicInteger flushCounter = new AtomicInteger(0);
    private static final String USER_ID = "user_id";

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {

        String key = this.extractKey(authentication);
        OAuth2AccessToken accessToken = this.authenticationToAccessTokenStore.get(key);

        if (!StringUtils.isEmpty(accessToken)
                && !StringUtils.isEmpty(this.readAuthentication(accessToken.getValue()))
                && !key.equals(this.extractKey(this.readAuthentication(accessToken.getValue())))) {
            this.storeAccessToken(accessToken, authentication);
        }

        if (!StringUtils.isEmpty(accessToken) &&
            !this.authenticationStore.get(accessToken.getValue()).getOAuth2Request().getRequestParameters().get(USER_ID).equals(authentication.getOAuth2Request().getRequestParameters().get(USER_ID))){
            return null;
        }
        return accessToken;
    }

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return this.readAuthentication(token.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {
        return this.authenticationStore.get(token);
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        return this.readAuthenticationForRefreshToken(token.getValue());
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(String token) {
        return this.refreshTokenAuthenticationStore.get(token);
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
            this.flush();
            this.flushCounter.set(0);
        }

        this.accessTokenStore.put(token.getValue(), token);
        this.authenticationStore.put(token.getValue(), authentication);
        this.authenticationToAccessTokenStore.put(this.extractKey(authentication), token);
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

    private String getApprovalKey(OAuth2Authentication authentication) {
        String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
        return this.getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
    }

    private String getApprovalKey(String clientId, String userName) {
        return clientId + (userName == null ? "" : ":" + userName);
    }

    private void addToCollection(ConcurrentHashMap<String, Collection<OAuth2AccessToken>> store, String key, OAuth2AccessToken token) {
        if (!store.containsKey(key)) {
            synchronized(store) {
                if (!store.containsKey(key)) {
                    store.put(key, new HashSet());
                }
            }
        }

        store.get(key).add(token);
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken accessToken) {
        this.removeAccessToken(accessToken.getValue());
    }

    @Override
    public OAuth2Authentication loadAuthentication(String tokenValue) throws AuthenticationException, InvalidTokenException {
        OAuth2AccessToken accessToken = this.readAccessToken(tokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + tokenValue);
        } else if (accessToken.isExpired()) {
            this.removeAccessToken(accessToken);
            throw new InvalidTokenException("Access token expired: " + tokenValue);
        }

        OAuth2Authentication result = this.readAuthentication(accessToken);
        log.info("result token {}: ", result);
        if (result == null) {
            throw new InvalidTokenException("Invalid access token: " + tokenValue);
        }
        if (clientDetailsService != null) {
            String clientId = result.getOAuth2Request().getClientId();
            try {
                clientDetailsService.loadClientByClientId(clientId);
            } catch (ClientRegistrationException e) {
                throw new InvalidTokenException("Client not valid: " + clientId, e);
            }
        }

        return result;
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        return this.accessTokenStore.get(tokenValue);
    }

    public void removeAccessToken(String tokenValue) {
        OAuth2AccessToken removed = this.accessTokenStore.remove(tokenValue);
        this.accessTokenToRefreshTokenStore.remove(tokenValue);
        OAuth2Authentication authentication = this.authenticationStore.remove(tokenValue);
        if (authentication != null) {
            this.authenticationToAccessTokenStore.remove(this.extractKey(authentication));
            String clientId = authentication.getOAuth2Request().getClientId();
            Collection<OAuth2AccessToken> tokens = this.userNameToAccessTokenStore.get(this.getApprovalKey(clientId, authentication.getName()));
            if (tokens != null) {
                tokens.remove(removed);
            }

            tokens = (Collection)this.clientIdToAccessTokenStore.get(clientId);
            if (tokens != null) {
                tokens.remove(removed);
            }

            this.authenticationToAccessTokenStore.remove(this.extractKey(authentication));
        }

    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        this.refreshTokenStore.put(refreshToken.getValue(), refreshToken);
        this.refreshTokenAuthenticationStore.put(refreshToken.getValue(), authentication);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
        return this.refreshTokenStore.get(tokenValue);
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
        this.removeRefreshToken(refreshToken.getValue());
    }

    public void removeRefreshToken(String tokenValue) {
        this.refreshTokenStore.remove(tokenValue);
        this.refreshTokenAuthenticationStore.remove(tokenValue);
        this.refreshTokenToAccessTokenStore.remove(tokenValue);
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        this.removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    private void removeAccessTokenUsingRefreshToken(String refreshToken) {
        String accessToken = this.refreshTokenToAccessTokenStore.remove(refreshToken);
        if (accessToken != null) {
            this.removeAccessToken(accessToken);
        }

    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        Collection<OAuth2AccessToken> result = this.userNameToAccessTokenStore.get(this.getApprovalKey(clientId, userName));
        return (result != null ? Collections.unmodifiableCollection(result) : Collections.emptySet());
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        Collection<OAuth2AccessToken> result = this.clientIdToAccessTokenStore.get(clientId);
        return (result != null ? Collections.unmodifiableCollection(result) : Collections.emptySet());
    }

    protected void flush() {
        for (TokenExpiry expiry = this.expiryQueue.poll(); expiry != null; expiry = this.expiryQueue.poll()) {
            this.removeAccessToken(expiry.getValue());
        }
    }

    static class TokenExpiry implements Delayed, Serializable {
        private static final long serialVersionUID = 1614139174242022935L;
        private final long expiry;
        private final String value;

        public TokenExpiry(String value, Date date) {
            this.value = value;
            this.expiry = date.getTime();
        }

        public int compareTo(Delayed other) {
            if (this == other) {
                return 0;
            } else {
                long diff = this.getDelay(TimeUnit.MILLISECONDS) - other.getDelay(TimeUnit.MILLISECONDS);
                return Long.compare(diff, 0L);
            }
        }

        public long getDelay(TimeUnit unit) {
            return this.expiry - System.currentTimeMillis();
        }

        public String getValue() {
            return this.value;
        }
    }

    public String extractKey(OAuth2Authentication authentication) {
        Map<String, String> values = new LinkedHashMap();
        OAuth2Request authorizationRequest = authentication.getOAuth2Request();
        if (!authentication.isClientOnly()) {
            values.put("username", authentication.getName());
        }

        values.put("client_id", authorizationRequest.getClientId());
        if (authorizationRequest.getScope() != null) {
            values.put("scope", OAuth2Utils.formatParameterList(new TreeSet(authorizationRequest.getScope())));
        }
        values.put(USER_ID, authorizationRequest.getRequestParameters().get(USER_ID));

        return this.generateKey(values);
    }

    protected String generateKey(Map<String, String> values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(values.toString().getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, bytes));
        } catch (NoSuchAlgorithmException var4) {
            throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).", var4);
        } catch (UnsupportedEncodingException var5) {
            throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).", var5);
        }
    }
}

