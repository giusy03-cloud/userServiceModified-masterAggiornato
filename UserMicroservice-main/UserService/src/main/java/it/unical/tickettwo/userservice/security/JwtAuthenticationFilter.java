package it.unical.tickettwo.userservice.security;

import java.io.IOException;

import it.unical.tickettwo.userservice.domain.UsersAccounts;
import it.unical.tickettwo.userservice.service.UsersAccountsService;
import it.unical.tickettwo.userservice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UsersAccountsService usersAccountsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            System.out.println("Token ricevuto: " + token);

            if (jwtUtil.validateToken(token)) {
                String username = jwtUtil.extractUsername(token);
                System.out.println("Username estratto dal token: " + username);

                UsersAccounts user = usersAccountsService.getUserByUsername(username);
                if (user == null) {
                    System.out.println("Utente NON trovato nel DB per username: " + username);
                } else {
                    System.out.println("Utente trovato: " + user.getUsername() + ", ruolo: " + user.getRole());
                    // Imposta l'autenticazione nel SecurityContext
                    List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } else {
                System.out.println("Token non valido");
            }
        }


        // Se manca il token, lascia passare (permetti ad altre configurazioni di decidere)
        filterChain.doFilter(request, response);
    }


}
