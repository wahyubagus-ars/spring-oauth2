package ars.spring.oauth2.domain.dao;

import lombok.*;
import org.codehaus.jackson.annotate.JsonIgnore;

import javax.persistence.*;

@Setter
@Getter
@Entity
@Table(name = "client_details")
@NoArgsConstructor
@AllArgsConstructor
public class ClientDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonIgnore
    private Client client;

    private String role;

}
