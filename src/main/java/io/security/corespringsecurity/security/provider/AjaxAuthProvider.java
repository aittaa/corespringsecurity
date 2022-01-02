package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AjaxAuthProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String)authentication.getCredentials();


        //id 검증
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        // pw 검증
        if(!passwordEncoder.matches(password, accountContext.getPassword())){
            throw new BadCredentialsException("BadCredentialsException");
        }

        /* 여기서 추가 검증 절차 진행 가능 */

        // 인증 토큰 생성 반환
        return new AjaxAuthToken(
                accountContext.getAccount(), null, accountContext.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthToken.class.isAssignableFrom(authentication);
    }
}
