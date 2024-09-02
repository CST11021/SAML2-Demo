package mujina.config;

import mujina.filter.ForceAuthnFilter;
import mujina.filter.SAMLAttributeAuthenticationFilter;
import mujina.idp.SAMLMessageHandler;
import mujina.service.LoginService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

/**
 * @Author 盖伦
 * @Date 2024/7/19
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private SAMLMessageHandler samlMessageHandler;

    @Resource
    private LoginService loginService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        // 静态资源的访问不需要拦截，直接放行
        web.ignoring().antMatchers("/favicon.ico", "/api/**", "/*.css", "/*.js");
        // 健康检查请求
        web.ignoring().antMatchers("/internal/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                // 校验用户名和密码
                .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                // 如果请求单点登录，则发送saml消息给客户端
                .addFilterBefore(new ForceAuthnFilter(samlMessageHandler), SAMLAttributeAuthenticationFilter.class)
                .authorizeRequests()
                // 放行接口
                .antMatchers("/", "/metadata").permitAll()
                // 必须要有ADMIN角色才能访问/admin/**
                .antMatchers("/admin/**").hasRole("ADMIN")
                // 除上面外的所有请求都需要有USER角色权限
                .anyRequest().hasRole("USER")
                .and()
                // 登录请求，默认: /login
                .formLogin()
                // 登录页面
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
     * 用于从HttpServletRequest获取属性的过滤器
     *
     * @return
     * @throws Exception
     */
    private SAMLAttributeAuthenticationFilter authenticationFilter() throws Exception {
        SAMLAttributeAuthenticationFilter filter = new SAMLAttributeAuthenticationFilter();

        filter.setAuthenticationManager(authenticationManagerBean());
        // 认证失败的跳转链接
        filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"));
        return filter;
    }

}