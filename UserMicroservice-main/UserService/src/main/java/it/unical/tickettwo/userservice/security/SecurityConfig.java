package it.unical.tickettwo.userservice.security;

import it.unical.tickettwo.userservice.domain.UsersAccounts;
import it.unical.tickettwo.userservice.service.UsersAccountsService;
import it.unical.tickettwo.userservice.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private UsersAccountsService usersAccountsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(csrf -> csrf.disable())



                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/users/*/exists").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/users").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**", "/api/users/me/oauth", "/api/users/hello/oauth").permitAll()  // aggiunto hello/oauth
                        // oppure più semplice per test: .requestMatchers("/api/users/**").permitAll()
                        .anyRequest().authenticated()
                )

                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService()))



                        .successHandler((request, response, authentication) -> {
                            OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
                            String email = oauthUser.getAttribute("email");
                            String name = oauthUser.getAttribute("name");

                            UsersAccounts user = usersAccountsService.getUserByUsername(email);

                            if (user == null) {
                                user = new UsersAccounts();
                                user.setUsername(email);
                                user.setName(name != null ? name : "Unknown");
                                user.setRole("PARTICIPANT");
                                user.setAccessType("OAUTH2");
                                usersAccountsService.save(user);
                            } else {
                                // Se l'utente esiste ma ruolo non è PARTICIPANT, aggiorna e salva
                                if (!"PARTICIPANT".equals(user.getRole())) {
                                    user.setRole("PARTICIPANT");
                                    usersAccountsService.save(user);
                                }
                            }

                            String jwtToken = JwtUtil.generateToken(user.getId(), user.getUsername(), user.getRole());
                            String encodedToken = URLEncoder.encode(jwtToken, StandardCharsets.UTF_8);
                            response.sendRedirect("http://localhost:4200/oauth-callback?token=" + encodedToken);
                        })

                )



                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
        return userRequest -> {
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            OAuth2User oauth2User = delegate.loadUser(userRequest);

            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name");

            var existingUser = usersAccountsService.getUserByUsername(email);
            if (existingUser == null) {
                var newUser = new it.unical.tickettwo.userservice.domain.UsersAccounts();
                newUser.setUsername(email);
                newUser.setPassword("GOOGLE_OAUTH"); // o null
                newUser.setRole("PARTICIPANT");
                newUser.setAccessType("GOOGLE");
                usersAccountsService.registerUser(newUser, null);
            } else {
                // Aggiorna ruolo se diverso da PARTICIPANT
                if (!"PARTICIPANT".equals(existingUser.getRole())) {
                    existingUser.setRole("PARTICIPANT");
                    usersAccountsService.save(existingUser);
                }
            }

            return oauth2User;
        };
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:4200", "http://localhost:8080", "http://localhost"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
