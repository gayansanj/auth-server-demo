package com.example.demo.filter;

import com.example.demo.util.SecurityConstants;
import com.example.demo.util.Utilities;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JWTVerifierFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String bearerToken = httpServletRequest.getHeader(SecurityConstants.HEADER);

        if(!(Utilities.validString(bearerToken) && bearerToken.startsWith(SecurityConstants.PREFIX))) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        String authToken = bearerToken.replace(SecurityConstants.PREFIX, "");
        System.out.println(authToken);
//        Optional<TokensEntity> tokensEntity = tokensRedisService.findById(authToken);

        if(StringUtils.isBlank(authToken)) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

//        String token = tokensEntity.get().getAuthenticationToken();
        Jws<Claims> authClaim = Jwts.parser().setSigningKey(SecurityConstants.KEY)
                .requireIssuer(SecurityConstants.ISSUER)
                .parseClaimsJws(authToken);

        String username = authClaim.getBody().getSubject();
        System.out.println(username);
        List<Map<String, String>> authorities = (List<Map<String, String>>) authClaim.getBody().get("authorities");
        List<GrantedAuthority> grantedAuthorities = authorities.stream().map(map -> new SimpleGrantedAuthority(map.get("authority")))
                .collect(Collectors.toList());
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        httpServletRequest.setAttribute("username", username);
        httpServletRequest.setAttribute("authorities", grantedAuthorities);
        System.out.println("authorities - " + grantedAuthorities);
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
