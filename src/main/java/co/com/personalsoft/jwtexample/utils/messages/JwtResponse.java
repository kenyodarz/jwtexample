package co.com.personalsoft.jwtexample.utils.messages;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class JwtResponse {
    private String token;
    private final String type = "Bearer";
    private String id;
    private String name;
    private String username;
    private String email;
    private List<String> roles;
}
