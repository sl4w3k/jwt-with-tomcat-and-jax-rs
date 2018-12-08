package pl.ailux.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.persistence.Id;

@Data
public class Item {
    @Id
    @JsonProperty(value = "username")
    private String id;
    @JsonProperty(value = "item-id")
    private String itemId;
    @JsonProperty(value = "item-name")
    private String itemName;
    @JsonProperty(value = "price")
    private double itemPrice;
    @JsonProperty(value = "quantity")
    private int itemQuantity;
}
