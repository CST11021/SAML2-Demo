package mujina.saml;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@EqualsAndHashCode(of = "nameID")
public class SAMLPrincipal implements Principal {

    /** SP的应用标识ID */
    private String serviceProviderEntityID;
    /**  */
    private String requestID;
    /** 登录成功后重定向的URL */
    private String assertionConsumerServiceURL;
    private String relayState;

    /** 用户名 */
    private String nameID;
    private String nameIDType;
    private final List<SAMLAttribute> attributes = new ArrayList<>();

    public SAMLPrincipal(String nameID, String nameIDType, List<SAMLAttribute> attributes) {
        this.nameID = nameID;
        this.nameIDType = nameIDType;
        this.attributes.addAll(attributes);
    }

    public SAMLPrincipal(String nameID, String nameIDType, List<SAMLAttribute> attributes, String serviceProviderEntityID, String requestID, String assertionConsumerServiceURL, String relayState) {
        this(nameID, nameIDType, attributes);
        this.serviceProviderEntityID = serviceProviderEntityID;
        this.requestID = requestID;
        this.assertionConsumerServiceURL = assertionConsumerServiceURL;
        this.relayState = relayState;
    }

    @Override
    public String getName() {
        return nameID;
    }

}
