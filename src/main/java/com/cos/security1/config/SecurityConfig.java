package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스트링 필터체인에 등록됨
// securedEnabled > secured 어노테이션 활성화, prePostEnabled > preAuthorized, postAuthorize 어노테이션 활성화
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해줌
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

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
                .loginPage("/loginForm")

                // 아래 주소 호출 시 시큐리티가 대신 로그인 진행
                .loginProcessingUrl("/login")

                // 로그인 성공시 아래 주소로 접속
                .defaultSuccessUrl("/");
    }
}
