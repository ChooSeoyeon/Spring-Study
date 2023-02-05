package com.cos.security1.config.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킴
// 이때, 로그인 진행 완료 되면 시큐리티 session을 만들어줌 (Security ContextHolder 라는 키 값에 세션 정보 저장시킴)
// 오브젝트 타입 => Authentication 타입의 객체
// Authentication 안에 User 정보가 있어야 됨.
// User 오브젝트의 타입 => UserDetails 타입 객체

// Security Session => Authentication => UserDetails(PrincipalDetails)

import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.userdetails.User; -> 이 녀석 떄문에 getRole 못썼음. model의 User를 써야하는데 시큐리티 userdetails의 User를 씀

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; //콤포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 User의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collect = new ArrayList<>(); // ArrayList는 Collection의 자식
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            } // user.getRole()을 반환하고 싶은데 String이라서 타입 GrantedAuthority으로 만들어줌
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정 만료됐니
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠겼니
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 계정 비밀번호 오래 사용했니
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화되어있니
    @Override
    public boolean isEnabled() {

        // 우리 사이트에서 1년동안 회원이 로그인을 안하면 휴먼 계정으로 전환하기러 함.
        // usre model에 loginDate같은 필드 필요함
        // 현재시간-로긴시간 => 1년 초과하면 return false;
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }
}
