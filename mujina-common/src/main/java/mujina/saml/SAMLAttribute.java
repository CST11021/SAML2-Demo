package mujina.saml;

import lombok.Data;

import java.util.List;

@Data
public class SAMLAttribute {

    private String name;
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
