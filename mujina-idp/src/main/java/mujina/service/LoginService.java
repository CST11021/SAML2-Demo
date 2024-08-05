package mujina.service;

import mujina.model.FederatedUserAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class LoginService implements AuthenticationProvider {

    /**
     * 登录认证
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (StringUtils.isEmpty(authentication.getPrincipal())) {
            throw new InvalidAuthenticationException("Principal may not be empty");
        }

        // 校验用户名和密码（证书）
        for (FederatedUserAuthenticationToken token : mockUser()) {
            if (token.getPrincipal().equals(authentication.getPrincipal()) &&
                    token.getCredentials().equals(authentication.getCredentials())) {
                return token.clone();
            }
        }

        throw new InvalidAuthenticationException("User not found or bad credentials");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private List<FederatedUserAuthenticationToken> mockUser() {
        List<FederatedUserAuthenticationToken> users = new ArrayList<>();
        users.addAll(Arrays.asList(
                new FederatedUserAuthenticationToken("admin", "admin",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"))),
                new FederatedUserAuthenticationToken("user", "secret",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")))));

        return users;
    }
}
