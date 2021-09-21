package dev.rexijie.oauth.oauth2server.model;

import com.fasterxml.jackson.annotation.*;

import java.util.Date;


@JsonPropertyOrder({"name","firstname", "lastname", "fullname", "email", "dob"})
@JsonIgnoreProperties({"userId"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfo extends Entity {
    private String userId;
    @JsonProperty("given_name")
    private String firstName;
    @JsonProperty("family_name")
    private String lastName;
    @JsonProperty("preferred_username")
    private String username;
    private String email;
    private boolean emailVerified;
    private OidcAddress address;
    @JsonProperty("phone_number")
    private String phoneNumber;
    @JsonProperty("phone_number_verified")
    private boolean phoneNumberVerified;
    @JsonProperty("birthdate")
    private Date dateOfBirth;
    @JsonProperty("picture")
    private String pictureUrl;

    @JsonProperty("name")
    public String getFullName() {
        return firstName +
                " " +
                lastName;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public OidcAddress getAddress() {
        return address;
    }

    public void setAddress(OidcAddress address) {
        this.address = address;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public void setPhoneNumberVerified(boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
    }

    public Date getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(Date dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public void setPictureUrl(String pictureUrl) {
        this.pictureUrl = pictureUrl;
    }

    @Override
    public String toString() {
        return "UserInfo{" +
                "firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", emailVerified=" + emailVerified +
                ", address=" + address +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", phoneNumberVerified=" + phoneNumberVerified +
                ", dateOfBirth=" + dateOfBirth +
                ", pictureUrl='" + pictureUrl + '\'' +
                '}';
    }
}
