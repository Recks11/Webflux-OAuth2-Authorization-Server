package dev.rexijie.oauth.oauth2server.model;

import com.fasterxml.jackson.annotation.JsonRootName;

/**
 * @author Rex Ijiekhuamen
 * 09 Sep 2020
 */
@JsonRootName("address")
public class OidcAddress {
    private String streetAddress;
    private String locality; // city
    private String region; // state
    private String postalCode;// zip/postcode
    private String country;

    public OidcAddress() {
    }

    public OidcAddress(String streetAddress, String locality, String region, String postalCode, String country) {
        this.streetAddress = streetAddress;
        this.locality = locality;
        this.region = region;
        this.postalCode = postalCode;
        this.country = country;
    }

    public String getStreetAddress() {
        return streetAddress;
    }

    public void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    @Override
    public String toString() {
        return "{" +
                "\"streetAddress\": \"" + streetAddress + '\"' +
                ", \"locality\": \"" + locality + '\"' +
                ", \"region\": \"" + region + '\"' +
                ", \"postalCode\": \"" + postalCode + '\"' +
                ", \"country\": \"" + country + '\"' +
                '}';
    }
}
