package com.example.proxy;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class StatelessUserAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
                // String username = request.getHeader("X-Auth-User");
                String username = "bill";
                System.out.println("[DEBUG] Request URI: " + request.getRequestURI());
                System.out.println("[DEBUG] X-Auth-User header: " + username);
                if(username != null) {
            User user = new User(username, "password", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
            request.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            System.out.println("[DEBUG] Set authentication for: " + user.getUsername());
            System.out.println("[DEBUG] After set: " + SecurityContextHolder.getContext().getAuthentication());
                }
        filterChain.doFilter(request, response);
    }
} 