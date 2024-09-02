package mujina.filter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class SAMLAttributeAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    @Override
    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        Map<String, String[]> needParam = new HashMap<>();

        Map<String, String[]> param = request.getParameterMap();
        for (Map.Entry<String, String[]> e : param.entrySet()) {
            // 过滤密码和用户名参数
            if (getPasswordParameter().equals(e.getKey()) || getUsernameParameter().equals(e.getKey())) {
                continue;
            }

            needParam.put(e.getKey(), e.getValue());
        }

        authRequest.setDetails(needParam);
    }

}
