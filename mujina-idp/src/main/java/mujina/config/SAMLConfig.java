package mujina.config;

import mujina.idp.SAMLMessageHandler;
import mujina.saml.KeyStoreLocator;
import mujina.saml.UpgradedSAMLBootstrap;
import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.util.VelocityFactory;

import javax.servlet.ServletContext;
import javax.servlet.SessionCookieConfig;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;

@Configuration
public class SAMLConfig /*implements WebMvcConfigurer*/ {

    @Value("${secure_cookie}")
    private boolean secureCookie;

    @Value("${idp.clock_skew}")
    private int clockSkew;
    @Value("${idp.expires}")
    private int expires;
    @Value("${idp.base_url}")
    private String idpBaseUrl;

    @Value("${idp.compare_endpoints}")
    private boolean compareEndpoints;


    @Value("${idp.entity_id}")
    private String idpEntityId;
    @Value("${idp.private_key}")
    private String idpPrivateKey;
    @Value("${idp.certificate}")
    private String idpCertificate;
    @Value("${idp.passphrase}")
    private String idpPassphrase;

    @Bean
    public SAMLMessageEncoder samlMessageEncoder() {
        return new HTTPPostSimpleSignEncoder(
                VelocityFactory.getEngine(),
                        "/templates/saml2-post-simplesign-binding.vm",
                true
        );
    }

    @Bean
    @Autowired
    public SAMLMessageHandler samlMessageHandler(IdpConfiguration idpConfiguration, JKSKeyManager keyManager)
            throws XMLParserException, URISyntaxException {
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        parserPool.initialize();

        BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
        securityPolicy.getPolicyRules().addAll(Arrays.asList(new IssueInstantRule(clockSkew, expires)));

        HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder(parserPool);
        HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder(parserPool);
        // 是否做url的比对
        if (!compareEndpoints) {
            URIComparator noopComparator = (uri1, uri2) -> true;
            httpRedirectDeflateDecoder.setURIComparator(noopComparator);
            httpPostDecoder.setURIComparator(noopComparator);
        }

        return new SAMLMessageHandler(
                keyManager,
                Arrays.asList(httpRedirectDeflateDecoder, httpPostDecoder),
                new StaticSecurityPolicyResolver(securityPolicy),
                idpConfiguration,
                idpBaseUrl);
    }

    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new UpgradedSAMLBootstrap();
    }

    @Bean
    public JKSKeyManager keyManager() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException,
            KeyStoreException, IOException {
        KeyStore keyStore = KeyStoreLocator.createKeyStore(idpPassphrase);
        KeyStoreLocator.addPrivateKey(keyStore, idpEntityId, idpPrivateKey, idpCertificate, idpPassphrase);
        return new JKSKeyManager(keyStore, Collections.singletonMap(idpEntityId, idpPassphrase), idpEntityId);
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        // 两个localhost实例会覆盖彼此的会话
        return new ServletContextInitializer() {

            @Override
            public void onStartup(ServletContext servletContext) {
                SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
                sessionCookieConfig.setName("mujinaIdpSessionId");
                sessionCookieConfig.setSecure(secureCookie);
                sessionCookieConfig.setHttpOnly(true);
            }

        };

    }

}
