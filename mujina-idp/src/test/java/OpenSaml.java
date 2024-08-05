import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.*;
import org.opensaml.common.SAMLVersion;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
 
import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
 
public class OpenSaml {

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }
 
    public void generateRequestURL() throws Exception {
          String consumerServiceUrl = "http://localhost:8080/consume.jsp";  // Set this for your app
          String website = "https://www.efesco.com";  // Set this for your app
 
          AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
          AuthnRequest authnRequest = authRequestBuilder.buildObject(SAMLConstants.SAML20P_NS, "AuthnRequest", "samlp");
          authnRequest.setIsPassive(false);
          authnRequest.setIssueInstant(new DateTime());
          authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
          authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
          authnRequest.setID(new BigInteger(130, new SecureRandom()).toString(42));
          authnRequest.setVersion(SAMLVersion.VERSION_20);
 
          IssuerBuilder issuerBuilder = new IssuerBuilder();
          Issuer issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp" );
          issuer.setValue(website);
          authnRequest.setIssuer(issuer);
 
          NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
          NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
          nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
          nameIdPolicy.setAllowCreate(true);
          authnRequest.setNameIDPolicy(nameIdPolicy);
 
          RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
          RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
          requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
          
          AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
          AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(SAMLConstants.SAML20_NS, "AuthnContextClassRef", "saml");
          authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
 
          requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
          authnRequest.setRequestedAuthnContext(requestedAuthnContext);
 
          Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
          Element authDOM = marshaller.marshall(authnRequest);

          StringWriter requestWriter = new StringWriter();
          XMLHelper.writeNode(authDOM, requestWriter);
          String messageXML = requestWriter.toString();
          System.out.println(messageXML);
 
    }

    public static void main(String[] args) throws Exception {
        OpenSaml openSaml = new OpenSaml();
        openSaml.generateRequestURL();
    }

}