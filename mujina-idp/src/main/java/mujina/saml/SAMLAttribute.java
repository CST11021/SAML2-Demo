package mujina.saml;

import lombok.Data;

import java.util.List;

@Data
public class SAMLAttribute {

    /** 属性名 */
    private String name;
    /** 属性值 */
    private List<String> values;

    public SAMLAttribute() {

    }

    public SAMLAttribute(String name, List<String> values) {
        this.name = name;
        this.values = values;
    }

    public String getName() {
        return name;
    }

    public List<String> getValues() {
        return values;
    }

    public String getValue() {
        return String.join(", ", values);
    }

    @Override
    public String toString() {
        return "SAMLAttribute{" +
                "name='" + name + '\'' +
                ", values=" + values +
                '}';
    }
}
