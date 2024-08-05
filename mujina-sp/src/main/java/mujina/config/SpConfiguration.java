package mujina.config;

import lombok.Getter;
import lombok.Setter;
import mujina.api.SharedConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
public class SpConfiguration extends SharedConfiguration {

    /** 在SAML中，entityID是用于唯一标识SAML实体（如身份提供者或服务提供者）的字符串。 */
    private String defaultEntityId;
    /** IDP的登录地址 */
    private String defaultIdpSSOServiceURL;
    /** IDP的登录地址 */
    private String idpSSOServiceURL;
    /** 登录的认证策略 */
    private String defaultProtocolBinding;
    /** 登录的认证策略 */
    private String protocolBinding;
    /** SP登录后的从定向地址 */
    private String defaultAssertionConsumerServiceURL;
    /** SP登录后的从定向地址 */
    private String assertionConsumerServiceURL;
    /** SP私钥 */
    private String spPrivateKey;
    /** SP证书 */
    private String spCertificate;
    private boolean defaultNeedsSigning;

    @Autowired
    public SpConfiguration(JKSKeyManager keyManager,
                           @Value("${sp.base_url}") String spBaseUrl,
                           @Value("${sp.entity_id}") String defaultEntityId,
                           @Value("${sp.single_sign_on_service_location}") String defaultIdpSSOServiceURL,
                           @Value("${sp.acs_location_path}") String defaultAssertionConsumerServiceURLPath,
                           @Value("${sp.protocol_binding}") String defaultProtocolBinding,
                           @Value("${sp.private_key}") String spPrivateKey,
                           @Value("${sp.certificate}") String spCertificate,
                           @Value("${sp.needs_signing}") boolean needsSigning) {
        super(keyManager);
        this.setDefaultEntityId(defaultEntityId);
        this.setDefaultIdpSSOServiceURL(defaultIdpSSOServiceURL);
        this.setDefaultAssertionConsumerServiceURL(spBaseUrl + defaultAssertionConsumerServiceURLPath);
        this.setDefaultProtocolBinding(defaultProtocolBinding);
        this.setSpPrivateKey(spPrivateKey);
        this.setSpCertificate(spCertificate);
        this.setDefaultNeedsSigning(needsSigning);
        reset();
    }

    @Override
    public void reset() {
        setEntityId(defaultEntityId, false);
        setNeedsSigning(defaultNeedsSigning);
        resetKeyStore(defaultEntityId, spPrivateKey, spCertificate);
        setIdpSSOServiceURL(defaultIdpSSOServiceURL);
        setProtocolBinding(defaultProtocolBinding);
        setAssertionConsumerServiceURL(defaultAssertionConsumerServiceURL);
        setSignatureAlgorithm(getDefaultSignatureAlgorithm());
    }

}
