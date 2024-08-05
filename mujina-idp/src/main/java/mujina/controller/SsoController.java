package mujina.controller;

import mujina.config.IdpConfiguration;
import mujina.idp.SAMLMessageHandler;
import mujina.model.FederatedUserAuthenticationToken;
import mujina.saml.SAMLAttribute;
import mujina.saml.SAMLPrincipal;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

@Controller
public class SsoController {

    @Autowired
    private SAMLMessageHandler samlMessageHandler;

    @Autowired
    private IdpConfiguration idpConfiguration;

    // 注：客户端需要配置改请求地址，进行登录

    /**
     * 单点登录服务
     *
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws MarshallingException
     * @throws SignatureException
     * @throws MessageEncodingException
     * @throws ValidationException
     * @throws SecurityException
     * @throws MessageDecodingException
     * @throws MetadataProviderException
     * @throws ServletException
     */
    @GetMapping("/SingleSignOnService")
    public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
        doSSO(request, response, authentication, false);
    }

    /**
     * 单点登录服务
     *
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws MarshallingException
     * @throws SignatureException
     * @throws MessageEncodingException
     * @throws ValidationException
     * @throws SecurityException
     * @throws MessageDecodingException
     * @throws MetadataProviderException
     * @throws ServletException
     */
    @PostMapping("/SingleSignOnService")
    public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
        doSSO(request, response, authentication, true);
    }

    /**
     *
     * @param request
     * @param response
     * @param authentication
     * @param postRequest
     * @throws ValidationException
     * @throws SecurityException
     * @throws MessageDecodingException
     * @throws MarshallingException
     * @throws SignatureException
     * @throws MessageEncodingException
     * @throws MetadataProviderException
     * @throws IOException
     * @throws ServletException
     */
    @SuppressWarnings("unchecked")
    private void doSSO(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest)
            throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException,
            MessageEncodingException, MetadataProviderException {


        SAMLPrincipal principal = buildSAMLPrincipal(request, response, authentication, postRequest);

        // 指定身份验证的级别
        String refs = determineAuthnContextClassRefs(authentication);

        // 登录成功后，通知浏览器重定向到跳转的url
        samlMessageHandler.sendAuthnResponse(principal, refs, response);
    }

    /**
     *
     *
     * @param request
     * @param response
     * @param authentication
     * @param postRequest       是否是post请求
     * @return
     */
    private SAMLPrincipal buildSAMLPrincipal(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest)
            throws ValidationException, MessageDecodingException, SecurityException, MetadataProviderException {

        SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest);
        AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

        // 获取属性
        List<SAMLAttribute> attributes = attributes(authentication);
        // 用户名
        String username = authentication.getName();
        // urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
        String nameIDType = attributes.stream()
                .filter(attr -> "urn:oasis:names:tc:SAML:1.1:nameid-format".equals(attr.getName()))
                .findFirst()
                .map(attr -> attr.getValue()).orElse(NameIDType.UNSPECIFIED);
        // http://mock-sp
        String serviceProviderEntityID = authnRequest.getIssuer().getValue();
        // a8j4e8g82e46bda48cf2176je7ce0g
        String requestID = authnRequest.getID();
        // 确定客户端要跳转的地址：http://localhost:9090/saml/SSO
        String assertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
        String relayState = messageContext.getRelayState();

        return new SAMLPrincipal(username, nameIDType, attributes, serviceProviderEntityID, requestID, assertionConsumerServiceURL, relayState);
    }

    /**
     * 确定身份验证的级别
     *
     * @param authentication
     * @return
     */
    private String determineAuthnContextClassRefs(Authentication authentication) {
        Map<String, String[]> parameterMap = (Map<String, String[]>) authentication.getDetails();

        String[] authnContextClassRefs = parameterMap.get("authn-context-class-ref-value");

        return authnContextClassRefs != null ? authnContextClassRefs[0] : AuthnContext.PASSWORD_AUTHN_CTX;
    }

    @SuppressWarnings("unchecked")
    private List<SAMLAttribute> attributes(Authentication authentication) {
        String uid = authentication.getName();

        // 保存用户相关的属性
        Map<String, List<String>> result = new HashMap<>(idpConfiguration.getAttributes());

        // 获取用户相关的属性
        Optional<Map<String, List<String>>> optionalMap = idpConfiguration.getUsers().stream()
                .filter(user -> user.getPrincipal().equals(uid))
                .findAny()
                .map(FederatedUserAuthenticationToken::getAttributes);
        optionalMap.ifPresent(result::putAll);


        //See SAMLAttributeAuthenticationFilter#setDetails
        Map<String, String[]> parameterMap = (Map<String, String[]>) authentication.getDetails();
        parameterMap.forEach((key, values) -> {
            result.put(key, Arrays.asList(values));
        });
        if (parameterMap.containsKey("authn-context-class-ref-value")) {
            result.remove("authn-context-class-ref-value");
        }

        Map<String, String> standardAttributes = idpConfiguration.getStandardAttributes().getAttributes();
        Map<String, List<String>> replacements = new HashMap<>();
        String mail = String.format("%s@%s",
                        uid.replaceAll("[^a-zA-Z0-9]", ""),
                        "example.com").toLowerCase();
        String givenName = uid.substring(0, 1).toUpperCase() + uid.substring(1);

        // 添加共享属性
        result.keySet().forEach(key -> {
            String standardValue = standardAttributes.get(key);
            List<String> resultValues = result.get(key);
            //Only override the attributes that were not entered by the user, e.g. equal the standard value
            if (StringUtils.hasText(standardValue) && !CollectionUtils.isEmpty(resultValues) &&
                    resultValues.get(0).equals(standardValue)) {
                switch (key) {
                    case "urn:mace:dir:attribute-def:cn":
                    case "urn:mace:dir:attribute-def:displayName":
                        replacements.put(key, List.of(givenName + " Doe"));
                        break;
                    case "urn:mace:dir:attribute-def:givenName":
                        replacements.put(key, List.of(givenName));
                        break;
                    case "urn:mace:dir:attribute-def:mail":
                    case "urn:mace:dir:attribute-def:eduPersonPrincipalName":
                    case "urn:oasis:names:tc:SAML:attribute:subject-id":
                        replacements.put(key, List.of(mail));
                        break;
                }
            }
        });
        result.putAll(replacements);
        //Provide the ability to limit the list attributes returned to the SP
        return result.entrySet().stream()
                .filter(entry -> !entry.getValue().stream().allMatch(StringUtils::isEmpty))
                .map(entry -> entry.getKey().equals("urn:mace:dir:attribute-def:uid") ?
                        new SAMLAttribute(entry.getKey(), singletonList(uid)) :
                        new SAMLAttribute(entry.getKey(), entry.getValue()))
                .collect(toList());
    }

}
