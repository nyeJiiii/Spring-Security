package com.cos.security1.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스트링 필터체인에 등록됨
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()

                // 아래 주소 접속 시 인증 필요
                .antMatchers("/user/**").authenticated()

                // 아래 주소 접속 시 인증 + admin or manager 권한 필요
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")

                // 아래 주소 접속 시 인증 + admin 권한 필요
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")

                // 그 이외 주소 접속 시 인증 필요 X
                .anyRequest().permitAll()

                // 권한이 없는 페이지로 접속 시 로그인 주소("/login")로 이동할 수 있도록 설정
                .and()
                .formLogin()
                .loginPage("/loginForm");
    }
}
