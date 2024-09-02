package mujina.config;

import lombok.Getter;
import lombok.Setter;
import mujina.saml.KeyStoreLocator;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.security.KeyStore;
import java.util.Enumeration;

@Getter
@Setter
@Component
@Configuration
public class IdpConfiguration implements InitializingBean {

    /** 在SAML中，entityID是用于唯一标识SAML实体（如身份提供者或服务提供者）的字符串。 */
    @Value("${idp.entity_id}")
    private String entityId;

    @Resource
    private JKSKeyManager keyManager;
    /** 秘钥库密码 */
    private String keystorePassword = "secret";
    @Value("${idp.private_key}")
    private String idpPrivateKey;
    @Value("${idp.certificate}")
    private String idpCertificate;

    /** 是否需要签名 */
    private boolean needsSigning;
    /** 签名算法 */
    private String signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;

    @Override
    public void afterPropertiesSet() throws Exception {

        KeyStore keyStore = keyManager.getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            keyStore.deleteEntry(aliases.nextElement());
        }
        KeyStoreLocator.addPrivateKey(keyStore, entityId, idpPrivateKey, idpCertificate, getKeystorePassword());



        BasicSecurityConfiguration.class.cast(
                org.opensaml.xml.Configuration.getGlobalSecurityConfiguration()
        ).registerSignatureAlgorithmURI("RSA", signatureAlgorithm);
    }

}
