package dev.rexijie.oauth.oauth2server.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.authority.Authority;

import java.util.Collections;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDTO {
    private String username;
    private String password;
    private String email;
    private Set<Authority> authorities;

    public UserDTO() {
    }

    public UserDTO(String username, String password) {
        this.username = username;
        this.password = password;
        this.email = null;
        this.authorities = Collections.emptySet();
    }

    public UserDTO(String username, String password, Set<Authority> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = Collections.unmodifiableSet(authorities);
    }

    public UserDTO(String username, String password, String email, Set<Authority> authorities) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.authorities = authorities;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<Authority> getAuthorities() {
        return authorities;
    }

    public String getEmail() {
        return email;
    }

//    public String[] getRawAuthorities() {
//        String[] auths = new String[getAuthorities().size()];
//        List<Authority> authorities = List.copyOf(getAuthorities());
//        for (int i = 0; i < auths.length; i++) {
//            auths[i] = authorities.get(i).toString();
//        }
//        return auths;
//    }

    @Override
    public String toString() {
        return "UserDTO {" +
                "username: '" + username + '\'' +
                ", password: '" + password + '\'' +
                ", authorities: " + authorities +
                '}';
    }

    public static class UserDTOMapper {
        public static User toUser(UserDTO userDTO) {
            return new User(
                    userDTO.getUsername(),
                    userDTO.getPassword(),
                    userDTO.getEmail(),
                    userDTO.getAuthorities());
        }

        public static UserDTO toDto(User user) {
            return new UserDTO(
                    user.getUsername(),
                    "[REDACTED]",
                    user.getAuthorities()
            );
        }
    }
}
