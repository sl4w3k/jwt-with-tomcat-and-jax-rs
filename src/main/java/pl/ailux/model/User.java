package pl.ailux.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.persistence.Id;
import java.util.ArrayList;
import java.util.List;

@Data
public class User {
    @Id
    @JsonProperty(value = "_id")
    private String id;
    @JsonProperty(value = "username")
    final private String username;
    @JsonProperty(value = "password")
    final private String password;
    @JsonProperty(value = "firm")
    private String firm;
    @JsonProperty(value = "roles")
    private List<String> rolesList = new ArrayList<>();
}
