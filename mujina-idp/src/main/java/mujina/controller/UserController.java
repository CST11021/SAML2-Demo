package mujina.controller;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Controller
public class UserController {

    @Value("${idp.saml_attributes_config_file}")
    private String samlAttributesConfigFile;


    @GetMapping("/")
    public String index(Authentication authentication) {
        return authentication == null ? "index" : "redirect:/user.html";
    }

    @GetMapping("/user.html")
    public String user(Authentication authentication, ModelMap modelMap) {
        modelMap.addAttribute("user", authentication);
        modelMap.addAttribute("userJson", JSONObject.toJSON(authentication));
        return "user";
    }

    @GetMapping("/login")
    public String login(ModelMap modelMap) throws IOException {

        ObjectMapper objectMapper = new ObjectMapper();
        DefaultResourceLoader loader = new DefaultResourceLoader();
        List<Map<String, String>> samlAttributes = objectMapper.readValue(
                loader.getResource(samlAttributesConfigFile).getInputStream(), new TypeReference<>() {});

        List<String> authnContextClassRefs = Lists.newArrayList(
                "一个测试的认证类型",
                "http://test2.surfconext.nl/assurance/loa1",
                "http://test2.surfconext.nl/assurance/loa1.5",
                "http://test2.surfconext.nl/assurance/loa2",
                "http://test2.surfconext.nl/assurance/loa3",
                "https://eduid.nl/trust/linked-institution",
                "https://eduid.nl/trust/validate-names",
                "https://eduid.nl/trust/affiliation-student",
                "https://refeds.org/profile/mfa"
        );

        // 获取saml属性
        modelMap.addAttribute("samlAttributes", samlAttributes);
        // 身份认证类别
        modelMap.addAttribute("authnContextClassRefs", authnContextClassRefs);
        return "login";
    }

}
