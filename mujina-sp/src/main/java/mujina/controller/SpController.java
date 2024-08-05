// package mujina.controller;
//
// import mujina.config.SpConfiguration;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
// import org.springframework.web.bind.annotation.PutMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;
//
// import javax.annotation.Resource;
//
// @RestController
// @RequestMapping(path = "/api", consumes = "application/json")
// public class SpController {
//
//     private final Logger LOG = LoggerFactory.getLogger(getClass());
//
//     @Resource
//     private SpConfiguration configuration;
//
//     @PutMapping(value = {"/ssoServiceURL"})
//     public void setSsoServiceURL(@RequestBody String ssoServiceURL) {
//         LOG.info("Request to set ssoServiceURL to {}", ssoServiceURL);
//         configuration.setIdpSSOServiceURL(ssoServiceURL);
//     }
//
//     @PutMapping("/protocolBinding")
//     public void setProtocolBinding(@RequestBody String protocolBinding) {
//         LOG.info("Request to set protocolBinding to {}", protocolBinding);
//         configuration.setProtocolBinding(protocolBinding);
//     }
//
//     @PutMapping("/assertionConsumerServiceURL")
//     public void setAssertionConsumerServiceURL(@RequestBody String assertionConsumerServiceURL) {
//         LOG.info("Request to set assertionConsumerServiceURL to {}", assertionConsumerServiceURL);
//         configuration.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
//     }
//
// }
