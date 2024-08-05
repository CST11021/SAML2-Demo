package mujina.config;

import mujina.filter.ForceAuthnFilter;
import mujina.service.LoginService;
import mujina.filter.SAMLAttributeAuthenticationFilter;
import mujina.idp.SAMLMessageHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @Author 盖伦
 * @Date 2024/7/19
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SAMLMessageHandler samlMessageHandler;

    @Autowired
    private LoginService loginService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().antMatchers("/internal/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                // 校验用户名和密码
                .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new ForceAuthnFilter(samlMessageHandler), SAMLAttributeAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "/metadata", "/favicon.ico", "/api/**", "/*.css", "/*.js").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().hasRole("USER")
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .failureUrl("/login?error=true")
                .permitAll()
                .and()
                .logout()
                .logoutSuccessUrl("/");
    }

    /**
     * 配置认证方式等
     *
     * @param auth the {@link AuthenticationManagerBuilder} to use
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        // 也有使用：auth.userDetailsService(mingYueUserDetailsService);方法实现
        auth.authenticationProvider(loginService);
    }

    /**
     *
     * @return
     * @throws Exception
     */
    private SAMLAttributeAuthenticationFilter authenticationFilter() throws Exception {
        SAMLAttributeAuthenticationFilter filter = new SAMLAttributeAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"));
        return filter;
    }

}