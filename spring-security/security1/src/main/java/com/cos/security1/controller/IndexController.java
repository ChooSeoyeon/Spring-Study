package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private UserRepository  userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) { // DI(의존성 주입)

        // 방법1
        System.out.println("/test/login==========================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // 구글로그인하고 들어오면 오류 남 -> test/oauth/login 따로 만들어줘야함
        System.out.println("authentication:" + principalDetails.getUser());

        // 방법2
        System.out.println(userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal OAuth2User oauth) { // DI(의존성 주입)

        // 방법1
        System.out.println("/test/oauth/login==========================");
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication:" + oauth2User.getAttributes());

        // 방법2
        System.out.println("oauth2User:"+oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"","/"})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    // 스프링시큐리티가 해당주소를 낚아채버림. 설정 필요 -> 이제 안낚아챔
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    // 회원가입 폼
    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){

        System.out.println(user);
        user.setRole("ROLE_USER");

        String rawPassword=user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);

        userRepository.save(user); // 회원가입 잘됨. 비밀번호: 1234 -> 시큐리티로 로그인 할 수 없음. 이유는 패스워드가 암호화가 안되어 있어서.
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {

        return "개인정보";
    }

    // @PostAuthorize 는 메소드가 끝나고 난 뒤에 실행됨. 잘안씀.
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // data라는 메소드가 실행되기 직전에 실행됨. ROLE_USER하면 안먹고, hasRole부터 써줘야함
    @GetMapping("/data")
    public @ResponseBody String data() {

        return "데이터정보";
    }

}
