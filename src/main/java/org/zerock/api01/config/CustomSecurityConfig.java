package org.zerock.api01.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.filter.APILoginFilter;
import org.zerock.api01.security.handler.APILoginSuccessHandler;

@Configuration
@Log4j2
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class CustomSecurityConfig {

    //주입
    private final APIUserDetailsService apiUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("----------web configure--------------");

        return (web) -> web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }

    /*

    - SpringBoot에서 이미 default로 SecurityFilterChain을 등록하는 데, @Bean객체로 다시 주입하게 되면서 둘 중 하나만 선택하라는 오류가 나타나는 것이다.

    @ConditionalOnDefaultWebSecurity
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    위 두 annotation을 class 위에 추가하고,

    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    위 annotation을 filter 함수 위에 추가하면 정상 작동이 된다.

    해결방법
    https://minkukjo.github.io/framework/2021/01/16/Spring-Security-04/

    */

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER) // boot 2.7+
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {

        //log.info("--------------------configure-------------------");

        //AuthenticationManager설정
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                        .passwordEncoder(passwordEncoder());

        //Get AuthenticationManager
        AuthenticationManager authenticationManager =
                authenticationManagerBuilder.build();

        // 반드시 필요
        http.authenticationManager(authenticationManager);

        // APILoginFilter
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);


        // APILoginSuccessHandler
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler();
        // SuccessHandler 세팅
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);


        // APILoginFilter의 위치 조정
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);


        http.csrf().disable();  //CSRF 토큰의 비활성화
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);    //세션을 사용하지 않음

        return http.build();
    }
}
