package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해줌
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll() // 위에 주소가 아닌 건 전부 permitAll
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행해줌 -> 컨트롤러에 안 만들어도 됨
                .defaultSuccessUrl("/") // 로그인 완료 시 메인 페이지로 감. 특정 페이지에서 로그인 요청하면 그 페이지로 돌려보내줌
                .and()
                .oauth2Login()
                .loginPage("/loginForm");
    }
}

/*
1. 구글 로그인 완료되면 구글서버에서 우리쪽으로 인증 되었다는 코드를 돌려줌
    http://localhost:8080/login/oauth2/code/google
        - 코드를 받기 위한 주소임
        - oauth 클라이언트라는 라이브러리 쓸 땐 이 주소 고정임. 다른 주소 사용 불가능함
        - 이에 대한 컨트롤러 주소 만들 필요 없음. 우리가 제어하는 게 아니고 라이브러리가 알아서 다 처리해줌
2. 우린 이 코드를 받아서 accessToken을 요청함
3. accessToken 받아서 사용자 대신에 서버가 구글서버에 사용자의 개인정보에 접근할 수 있는 권한 생김
 */