package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // req.setCharacterEncoding("UTF-8"); // Authorization엔 정책 상 한글 들어갈 수 없음

        // 실제 로직
        // 토큰 이름 : cos <- 이걸 만들어줘야함. id, pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
        // 요청할 때마다 header에 Authorization에 value값으로 토큰을 가지고 옴
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨. (RSA, HS256)

        // 테스트 로직
        // 토큰 이름 : cos
        // cos라는 토큰 넘어오면 필터 계속 타서 인증되게하고, 그게 아니면 더이상 필터 못타게 해서 컨트롤러에 진입조차 못하게 함
        if (req.getMethod().equals("POST")) { // post일 때만 동작
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터3");

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res); // 프로그램 끝나지 말고 프로세스 계속 진행하게 하기 위함
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }
        }
    }
}