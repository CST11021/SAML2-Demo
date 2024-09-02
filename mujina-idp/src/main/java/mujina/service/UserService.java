package mujina.service;

import mujina.model.UserAuthToken;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @Author 盖伦
 * @Date 2024/9/2
 */
@Service
public class UserService implements InitializingBean {

    private List<UserAuthToken> users = new ArrayList<>();

    @Override
    public void afterPropertiesSet() throws Exception {
        users.clear();
        users.addAll(Arrays.asList(
                new UserAuthToken("admin", "admin",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"))),
                new UserAuthToken("user", "secret",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")))));
    }

    public List<UserAuthToken> getAllUsers() {
        return users;
    }

}
