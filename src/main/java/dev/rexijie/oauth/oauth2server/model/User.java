package dev.rexijie.oauth.oauth2server.model;

import dev.rexijie.oauth.oauth2server.model.authority.Authority;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.userdetails.UserDetails;

import javax.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

@Document
public class User extends Entity implements UserDetails {
    @NotBlank(message = "username can not be empty")
    private String username;
    private String email;
    @NotBlank(message = "password cannot be empty")
    private String password;
    private Set<Authority> authorities;
    private transient UserInfo userInfo;
    private boolean isEnabled;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;

    public User() {
        this.userInfo = new UserInfo();
    }

    public User(String username, String password, Set<Authority> authorities) {
        this(username, password, null, authorities);
    }

    public User(String username, String password, String email, Set<Authority> authorities) {
        this();
        setUsername(username);
        setPassword(password);
        setAuthorities(authorities);
        setEmail(email);
    }

    public User(String username, String password, Set<Authority> authorities, UserInfo userInfo) {
        this(username, password, null, authorities);
        setUserInfo(userInfo);
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
        getUserInfo().setUsername(username);
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
        this.userInfo.setEmail(email);
    }

    public void setAuthorities(Set<Authority> authorities) {
        this.authorities = Collections.unmodifiableSet(authorities);
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(UserInfo userInfo) {
        userInfo.setUserId(this.getId());
        this.userInfo = userInfo;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    @Override
    public Set<Authority> getAuthorities() {
        return this.authorities;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    @Override
    public void setCreatedAt(LocalDateTime createdAt) {
        super.setCreatedAt(createdAt);
        getUserInfo().setCreatedAt(createdAt);
    }

    @Override
    public void setUpdatedAt(LocalDateTime updatedAt) {
        super.setUpdatedAt(updatedAt);
        getUserInfo().setUpdatedAt(updatedAt);
    }

    @Override
    public String toString() {
        return "User" + " {" +
                "Username: " + this.username + "; " +
                "Password: [PROTECTED]; " +
                "Profile: [PROTECTED]; " +
                "Authorities: [" + this.authorities.size() + " Authorities]" + "; " +
                "Enabled: " + this.isEnabled + "; " +
                "AccountNonExpired: " + this.accountNonExpired + "; " +
                "credentialsNonExpired: " + this.credentialsNonExpired + "; " +
                "AccountNonLocked: " + this.accountNonLocked + "; " +
                " }";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        User user = (User) o;
        return username.equals(user.username) &&
                authorities.equals(user.authorities) &&
                Objects.equals(userInfo, user.userInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), username, authorities, userInfo);
    }
}
