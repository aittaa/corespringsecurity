package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FormAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        // 클라이언트 popup

        String errMsg = "";

        if(exception instanceof UsernameNotFoundException){
            errMsg = "Invalid Username";
        }else if(exception instanceof BadCredentialsException){
            errMsg = "Invalid Password";
        } else if (exception instanceof InsufficientAuthenticationException){
            errMsg = "Invalid Secret Key";
        }


        setDefaultFailureUrl("/login?error=true&exception=" + errMsg);

        super.onAuthenticationFailure(request, response, exception);

    }
}
