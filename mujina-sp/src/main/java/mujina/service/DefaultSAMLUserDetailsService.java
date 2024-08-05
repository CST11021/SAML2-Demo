package mujina.service;

import mujina.saml.SAMLAttribute;
import mujina.saml.SAMLBuilder;
import mujina.saml.SAMLPrincipal;
import org.apache.commons.collections4.CollectionUtils;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Comparator.comparing;

@Service
public class DefaultSAMLUserDetailsService implements SAMLUserDetailsService {

    @Override
    public Principal loadUserBySAML(SAMLCredential credential) {

        List<SAMLAttribute> attributes = new ArrayList<>();
        for (Attribute attribute : credential.getAttributes()) {
            SAMLAttribute samlAttribute = new SAMLAttribute();
            samlAttribute.setName(attribute.getName());
            samlAttribute.setValues(getValue(attribute));
        }

        // 给属性排下序
        attributes.sort(comparing(SAMLAttribute::getName));
        return new SAMLPrincipal(credential.getNameID().getValue(), credential.getNameID().getFormat(), attributes);
    }

    /**
     *
     * @param attribute
     * @return
     */
    private List<String> getValue(Attribute attribute) {
        if (CollectionUtils.isEmpty(attribute.getAttributeValues())) {
            return new ArrayList<>();
        }

        List<String> valueList = new ArrayList<>();
        for (XMLObject xmlObject : attribute.getAttributeValues()) {

            Optional<String> optional = SAMLBuilder.getStringValueFromXMLObject(xmlObject);
            if (optional.isPresent()) {
                valueList.add(optional.get());
            }
        }
        return valueList;
    }

}
