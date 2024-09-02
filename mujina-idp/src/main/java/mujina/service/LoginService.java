package mujina.service;

import mujina.model.UserAuthToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class LoginService implements AuthenticationProvider {

    @Resource
    private UserService userService;

    /**
     * 登录认证
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 在Spring Boot Security中，Principal通常代表经过身份验证的用户，Credentials代表用户或实体用于验证身份的证书、密码或其他安全凭据
        if (authentication.getPrincipal() == null) {
            throw new InvalidAuthenticationException("用户名不能为空");
        }

        // 校验用户名和密码（证书）
        for (UserAuthToken token : userService.getAllUsers()) {
            if (token.getPrincipal().equals(authentication.getPrincipal()) &&
                    token.getCredentials().equals(authentication.getCredentials())) {
                return token.clone();
            }
        }

        throw new InvalidAuthenticationException("用户不存在或者密码（证书）错误");
    }

    /**
     * 是否支持当前的认证类型
     *
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
