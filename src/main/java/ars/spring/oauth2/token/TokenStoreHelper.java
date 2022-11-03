package ars.spring.oauth2.token;

import ars.spring.oauth2.component.SessionStorage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class TokenStoreHelper {

//    @Autowired
//    SessionStorage sessionStorage;

    private final DelayQueue<TokenStoreCustomizer.TokenExpiry> expiryQueue = new DelayQueue();
    protected final AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
    protected void flush() {
        for (TokenStoreCustomizer.TokenExpiry expiry = this.expiryQueue.poll(); expiry != null; expiry = this.expiryQueue.poll()) {
            this.removeAccessToken(expiry.getValue());
        }
    }

    protected String getSecondKey(OAuth2Authentication authentication) {
        return authentication.getOAuth2Request().getRequestParameters().get("user_id");
    }
    protected void removeAccessToken(String tokenValue) {
        //var oAuth2Authentication = (OAuth2Authentication) sessionStorage.getCache(KEY_USER_SESSION, KEY_OAUTH_AUTHENTICATION.concat(tokenValue));

        //removed access oauth access token
        //sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_ACCESS_REFRESH_TOKEN.concat(tokenValue));
        //sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_TOKEN_EXPIRY.concat(tokenValue));

        var secondKey = "";
        var clientId = "";

//        if (null != oAuth2Authentication) {
//            secondKey = getSecondKey(oAuth2Authentication);
//            clientId = oAuth2Authentication.getOAuth2Request().getClientId();
//            sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_ACCESS_TOKEN.concat(this.authenticationKeyGenerator.extractKey(oAuth2Authentication).concat(secondKey)));
//            sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_ACCESS_TOKEN.concat(getApprovalKey(clientId, secondKey)));
//        }

        //removed access oauth access authentication
//        var oAuth2AuthenticationPersist = (OAuth2Authentication) sessionStorage.removeCachePersist(KEY_USER_SESSION, KEY_OAUTH_AUTHENTICATION.concat(tokenValue));
//
//        if (null != oAuth2AuthenticationPersist) {
//            var oAuth2AccessToken = (OAuth2AccessToken) sessionStorage
//                    .removeCachePersist(KEY_USER_SESSION, KEY_OAUTH_ACCESS_TOKEN.concat(tokenValue));
//            sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_ACCESS_TOKEN.concat(this.authenticationKeyGenerator.extractKey(oAuth2Authentication).concat(secondKey)));
//            Collection<OAuth2AccessToken> tokens = (Collection<OAuth2AccessToken>) sessionStorage.getCache(KEY_USER_SESSION, (KEY_OAUTH_ACCESS_TOKEN.concat(getApprovalKey(clientId, secondKey))));
//
//            if (null != tokens) {
//                tokens.remove(oAuth2AccessToken);
//            }

//            tokens = (Collection<OAuth2AccessToken>) sessionStorage.getCache(KEY_USER_SESSION, KEY_OAUTH_ACCESS_TOKEN.concat(clientId));
//            if (null != tokens) {
//                tokens.remove(oAuth2AccessToken);
//            }
//            sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_ACCESS_TOKEN.concat(this.authenticationKeyGenerator.extractKey(oAuth2Authentication)));
//            sessionStorage.removeCache(KEY_USER_SESSION, KEY_OAUTH_DETAILS.concat(tokenValue));
        //}
    }

    protected String getApprovalKey(OAuth2Authentication authentication) {
        String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
        return this.getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);

    }

    protected String getApprovalKey(String clientId, String userName) {
        return clientId + (userName == null ? "" : ":" + userName);
    }

    protected void addToCollection(ConcurrentHashMap<String, Collection<OAuth2AccessToken>> store, String key, OAuth2AccessToken token) {
        if (!store.containsKey(key)) {
            synchronized(store) {
                if (!store.containsKey(key)) {
                    store.put(key, new HashSet());
                }
            }
        }

        ((Collection)store.get(key)).add(token);
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
}
