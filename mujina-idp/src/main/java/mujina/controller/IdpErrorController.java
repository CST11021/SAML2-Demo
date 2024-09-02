package mujina.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestController
@RequestMapping("/error")
public class IdpErrorController implements ErrorController {

    @Autowired
    private ErrorAttributes errorAttributes;

    @RequestMapping
    public ResponseEntity<Map<String, Object>> error(HttpServletRequest aRequest) {
        ServletWebRequest webRequest = new ServletWebRequest(aRequest);
        Map<String, Object> result = this.errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults());

        HttpStatus statusCode = INTERNAL_SERVER_ERROR;
        Object status = result.get("status");
        if (status != null && status instanceof Integer) {
            statusCode = HttpStatus.valueOf(((Integer) status).intValue());
        }
        return new ResponseEntity<>(result, statusCode);

    }

}
