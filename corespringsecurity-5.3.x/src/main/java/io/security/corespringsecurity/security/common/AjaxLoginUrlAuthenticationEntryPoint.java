package io.security.corespringsecurity.security.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
인가처리
AbstractSecurityInterceptor - 해당 자원을 접근할려고 할때 자격이 되는지 검증하는 필터

1. 인증을 받지 않았을때(익명 사용자) 해당 자원을 접근 할때  -> authenticationEntryPoint 호출한다. (로그인 할 수 있도록 호출함)

2. 인증을 받았는데 해당 자원을 접근 할때 -> accessDeniedHandler 호출한다.


AccessDeniedException 이 발생되면서 ExceptionTranslationFilter 가 받아서 1,2번 분기 처리한다.
 */

public class AjaxLoginUrlAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(HttpServletResponse.SC_UNAUTHORIZED));
    }
}
