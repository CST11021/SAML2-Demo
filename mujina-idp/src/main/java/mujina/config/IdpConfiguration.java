package mujina.config;

import lombok.Getter;
import lombok.Setter;
import mujina.api.SharedConfiguration;
import mujina.model.FederatedUserAuthenticationToken;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.stereotype.Component;

import java.util.*;

@Getter
@Setter
@Component
@Configuration
public class IdpConfiguration extends SharedConfiguration implements InitializingBean {

    /** 在SAML中，entityID是用于唯一标识SAML实体（如身份提供者或服务提供者）的字符串。 */
    @Value("${idp.entity_id}")
    private String defaultEntityId;
    @Value("${idp.private_key}")
    private String idpPrivateKey;
    @Value("${idp.certificate}")
    private String idpCertificate;


    @Autowired
    private StandardAttributes standardAttributes;

    private Map<String, List<String>> attributes = new TreeMap<>();
    private List<FederatedUserAuthenticationToken> users = new ArrayList<>();

    @Autowired
    public IdpConfiguration(JKSKeyManager keyManager) {
        super(keyManager);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        // this.defaultAuthenticationMethod = AuthenticationMethod.valueOf(authMethod);
        reset();
    }

    @Override
    public void reset() {
        setEntityId(defaultEntityId);
        resetAttributes();
        resetKeyStore(defaultEntityId, idpPrivateKey, idpCertificate);
        resetUsers();
        // setAuthenticationMethod(this.defaultAuthenticationMethod);
        setSignatureAlgorithm(getDefaultSignatureAlgorithm());
    }

    /**
     * 设置账户
     * 注：在Spring Boot Security中，Principal通常代表经过身份验证的用户，Credentials代表用户或实体用于验证身份的证书、密码或其他安全凭据。
     */
    private void resetUsers() {
        users.clear();
        users.addAll(Arrays.asList(
                new FederatedUserAuthenticationToken("admin", "admin",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"))),
                new FederatedUserAuthenticationToken("user", "secret",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")))));
    }

    private void resetAttributes() {
        Map<String, String> configuredAttributes = standardAttributes.getAttributes();

        attributes.clear();
        for (Map.Entry<String, String> attribute : configuredAttributes.entrySet()) {
            this.attributes.put(attribute.getKey(), Arrays.asList(attribute.getValue()));
        }

    }

}
