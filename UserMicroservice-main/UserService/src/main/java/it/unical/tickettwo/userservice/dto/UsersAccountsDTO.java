package it.unical.tickettwo.userservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonProperty;

@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UsersAccountsDTO {
    @JsonProperty
    private long id;

    @JsonProperty
    private String name;

    @JsonProperty
    private String username;

    @JsonProperty
    private String role;

    @JsonProperty
    private String accessType;

    public UsersAccountsDTO(long id, String name, String username, String role, String accessType) {
        this.id = id;
        this.name=name;
        this.username = username;
        this.role = role;
        this.accessType = accessType;
    }
}

