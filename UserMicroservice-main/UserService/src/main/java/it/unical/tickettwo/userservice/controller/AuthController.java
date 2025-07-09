package it.unical.tickettwo.userservice.controller;

import it.unical.tickettwo.userservice.util.JwtUtil;
import it.unical.tickettwo.userservice.domain.UsersAccounts;
import it.unical.tickettwo.userservice.dto.UsersAccountsDTO;
import it.unical.tickettwo.userservice.service.UsersAccountsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(value = "http://localhost:4200", allowCredentials = "true")
@RequestMapping("/auth")
public class AuthController {

    private static class AuthToken {
        private String token;
        private UsersAccountsDTO user;

        public UsersAccountsDTO getUser() {
            return user;
        }

        public void setUser(UsersAccountsDTO user) {
            this.user = user;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }

    @Autowired
    private UsersAccountsService usersAccountsService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UsersAccounts user, HttpServletRequest request) {
        String username = user.getUsername();
        String password = user.getPassword();

        System.out.println("Username login: " + username);
        System.out.println("Password login (plaintext): " + password);

        UsersAccounts storedUser = usersAccountsService.getUserByUsername(username);
        if (storedUser != null) {
            System.out.println("Stored password hash: " + storedUser.getPassword());
        } else {
            System.out.println("Utente non trovato per username: " + username);
        }

        if (storedUser != null && passwordEncoder.matches(password, storedUser.getPassword())) {
            // ✅ CREA LA SESSIONE
            HttpSession session = request.getSession(true);
            session.setAttribute("username", username); // o salva altro se ti serve

            String token = JwtUtil.generateToken(storedUser.getId(), storedUser.getUsername(), storedUser.getRole());

            System.out.println("Token generato: " + token);

            UsersAccountsDTO userDTO = new UsersAccountsDTO(
                    storedUser.getId(),
                    storedUser.getName(),
                    storedUser.getUsername(),
                    storedUser.getRole(),
                    storedUser.getAccessType()
            );

            AuthToken auth = new AuthToken();
            auth.setToken(token);
            auth.setUser(userDTO);
            return ResponseEntity.ok(auth);
        } else {
            System.out.println("Password non corrisponde o utente non trovato");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Username o password errati");
        }
    }


    @PostMapping("/logout")
    public boolean logout(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session != null) {
            System.out.println("user Logging out");
            session.invalidate();
            return true;
        }
        return false;
    }

    @PostMapping("/isAuthenticated")
    public boolean isAuthenticated(HttpServletRequest req) {
        String authHeader = req.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return JwtUtil.validateToken(token);
        }

        return false;
    }

    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getCurrentUser(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization header missing or invalid");
        }
        String token = authHeader.substring(7);
        if (!JwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token invalid or expired");
        }
        String username = JwtUtil.extractUsername(token);
        UsersAccounts user = usersAccountsService.getUserByUsername(username);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
        }
        UsersAccountsDTO dto = new UsersAccountsDTO(
                user.getId(),
                user.getName(),
                user.getUsername(),
                user.getRole(),
                user.getAccessType()
        );
        return ResponseEntity.ok(dto);
    }

}
