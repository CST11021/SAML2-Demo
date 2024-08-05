package mujina.idp;

import mujina.config.IdpConfiguration;
import mujina.saml.ProxiedSAMLContextProviderLB;
import mujina.saml.SAMLBuilder;
import mujina.saml.SAMLPrincipal;
import org.joda.time.DateTime;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;

import static java.util.Arrays.asList;
import static mujina.saml.SAMLBuilder.*;
import static org.opensaml.xml.Configuration.getValidatorSuite;

public class SAMLMessageHandler {

    /** 秘钥管理器 */
    private final KeyManager keyManager;
    /** SAML消息解码 */
    private final Collection<SAMLMessageDecoder> decoders;
    /** SAML消息编码 */
    @Resource
    private SAMLMessageEncoder encoder;
    private final SecurityPolicyResolver resolver;
    private final IdpConfiguration idpConfiguration;

    private final List<ValidatorSuite> validatorSuites;
    private final ProxiedSAMLContextProviderLB proxiedSAMLContextProviderLB;

    public SAMLMessageHandler(KeyManager keyManager, Collection<SAMLMessageDecoder> decoders,
                              SecurityPolicyResolver securityPolicyResolver,
                              IdpConfiguration idpConfiguration, String idpBaseUrl) throws URISyntaxException {
        this.keyManager = keyManager;
        this.decoders = decoders;
        this.resolver = securityPolicyResolver;
        this.idpConfiguration = idpConfiguration;
        this.validatorSuites = asList(
                getValidatorSuite("saml2-core-schema-validator"),
                getValidatorSuite("saml2-core-spec-validator"));
        this.proxiedSAMLContextProviderLB = new ProxiedSAMLContextProviderLB(new URI(idpBaseUrl));
    }

    /**
     * 抽取SAMLMessageContext
     *
     * @param request
     * @param response
     * @param postRequest
     * @return
     * @throws ValidationException
     * @throws SecurityException
     * @throws MessageDecodingException
     * @throws MetadataProviderException
     */
    public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request, HttpServletResponse response, boolean postRequest)
            throws ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {

        // 创建SAMLMessageContext
        SAMLMessageContext messageContext = creatSAMLMessageContext(request, response);
        messageContext.setSecurityPolicyResolver(resolver);

        // 做解码
        doDecode(messageContext, postRequest);

        // 做校验
        AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
        for (ValidatorSuite validatorSuite : validatorSuites) {
            validatorSuite.validate(authnRequest);
        }
        return messageContext;
    }

    private SAMLMessageContext creatSAMLMessageContext(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext messageContext = new SAMLMessageContext();
        proxiedSAMLContextProviderLB.populateGenericContext(request, response, messageContext);

        return messageContext;
    }

    private void doDecode(SAMLMessageContext messageContext, boolean postRequest) throws MessageDecodingException, SecurityException {
        // 解码
        SAMLMessageDecoder samlMessageDecoder = findSamlMessageDecoder(postRequest);
        if (samlMessageDecoder == null) {
            throw new RuntimeException(String.format("Only %s and %s are supported",
                    SAMLConstants.SAML2_REDIRECT_BINDING_URI,
                    SAMLConstants.SAML2_POST_BINDING_URI));
        }

        samlMessageDecoder.decode(messageContext);
    }

    private SAMLMessageDecoder findSamlMessageDecoder(boolean postRequest) {
        String bindingUri = postRequest ? SAMLConstants.SAML2_POST_BINDING_URI : SAMLConstants.SAML2_REDIRECT_BINDING_URI;

        for (SAMLMessageDecoder decoder : decoders) {
            if (decoder.getBindingURI().equals(bindingUri)) {
                return decoder;
            }
        }

        return null;
    }

    /**
     * 发送SAML响应
     *
     * @param principal                 用户信息
     * @param authnContextClassRefValue 身份验证的级别
     * @param response
     * @throws MarshallingException
     * @throws SignatureException
     * @throws MessageEncodingException
     */
    public void sendAuthnResponse(SAMLPrincipal principal, String authnContextClassRefValue, HttpServletResponse response)
            throws MarshallingException, SignatureException, MessageEncodingException {
        Status status = buildStatus(StatusCode.SUCCESS_URI);

        String entityId = idpConfiguration.getEntityId();
        Credential signingCredential = resolveCredential(entityId);

        Response authResponse = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
        authResponse.setIssuer(buildIssuer(entityId));
        authResponse.setID(SAMLBuilder.randomSAMLId());
        authResponse.setIssueInstant(new DateTime());
        authResponse.setInResponseTo(principal.getRequestID());

        Assertion assertion = buildAssertion(principal, authnContextClassRefValue, status, entityId);
        signAssertion(assertion, signingCredential);

        authResponse.getAssertions().add(assertion);
        authResponse.setDestination(principal.getAssertionConsumerServiceURL());
        authResponse.setStatus(status);

        Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        endpoint.setLocation(principal.getAssertionConsumerServiceURL());





        BasicSAMLMessageContext message = new BasicSAMLMessageContext();
        message.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));
        // SingleSignOnServiceImpl
        message.setPeerEntityEndpoint(endpoint);
        message.setOutboundSAMLMessage(authResponse);
        // BasicX509Credential
        message.setOutboundSAMLMessageSigningCredential(signingCredential);
        // http://mock-idp
        message.setOutboundMessageIssuer(entityId);
        message.setRelayState(principal.getRelayState());
        // 将编码的SAML响应返回给浏览器
        encoder.encode(message);

    }

    private Credential resolveCredential(String entityId) {
        try {
            return keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        }
    }

}
