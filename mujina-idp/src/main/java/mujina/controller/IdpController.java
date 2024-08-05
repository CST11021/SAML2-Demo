package mujina.controller;

import mujina.config.IdpConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(path = "/api", consumes = "application/json")
public class IdpController /* extends SharedController */ {

    private final Logger LOG = LoggerFactory.getLogger(getClass());

    @Resource
    private IdpConfiguration configuration;

    @PutMapping("/attributes")
    public void setAttributes(@RequestBody Map<String, List<String>> attributes) {
        LOG.info("Request to replace all attributes {}", attributes);
        configuration.setAttributes(attributes);
    }

    @PutMapping("/attributes/{name:.+}")
    public void setAttribute(@PathVariable String name, @RequestBody List<String> values) {
        LOG.info("Request to set attribute {} to {}", name, values);
        configuration.getAttributes().put(name, values);
    }

    @PutMapping("/attributes/{name:.+}/{userName:.+}")
    public void setAttributeForUser(@PathVariable String name, @PathVariable String userName,
                                    @RequestBody List<String> values) {
        LOG.info("Request to set attribute {} to {} for user {}", name, values, userName);
        configuration.getUsers().stream().filter(userAuthenticationToken -> userAuthenticationToken.getName().equals
                (userName)).findFirst().orElseThrow(() -> new IllegalArgumentException(String.format("User %s first " +
                "must be created", userName))).getAttributes().put(name, values);
    }

    @DeleteMapping("/attributes/{name:.+}")
    public void removeAttribute(@PathVariable String name) {
        LOG.info("Request to remove attribute {}", name);
        configuration.getAttributes().remove(name);
    }

    @DeleteMapping("/attributes/{name:.+}/{userName:.+}")
    public void removeAttributeForUser(@PathVariable String name, @PathVariable String userName) {
        LOG.info("Request to remove attribute {} for user {}", name, userName);
        configuration.getUsers().stream().filter(userAuthenticationToken -> userAuthenticationToken.getName().equals
                (userName)).findFirst().orElseThrow(() -> new IllegalArgumentException(String.format("User %s first " +
                "must be created", userName))).getAttributes().remove(name);
    }


}
