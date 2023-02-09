package com.cos.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        System.out.println("필터1"); // 프로그램 끝나지 말고 프로세스 계속 진행하게 하기 위함
        chain.doFilter(request, response);
    }
}