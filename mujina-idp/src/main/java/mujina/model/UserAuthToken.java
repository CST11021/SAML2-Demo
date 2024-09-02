package mujina.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 联邦用户认证的令牌
 */
@Getter
@Setter
public class UserAuthToken extends UsernamePasswordAuthenticationToken {

    /** 用于存储令牌包含的其他扩展信息 */
    private Map<String, List<String>> attributes = new TreeMap<>();

    /**
     * 在Spring Boot Security中，Principal通常代表经过身份验证的用户，Credentials代表用户或实体用于验证身份的证书、密码或其他安全凭据。
     *
     * @param principal
     * @param credentials
     * @param authorities
     */
    public UserAuthToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public UserAuthToken clone() {
        UserAuthToken clone = new UserAuthToken(getPrincipal(), getCredentials(), getAuthorities());
        clone.setAttributes(attributes);
        return clone;
    }
}
