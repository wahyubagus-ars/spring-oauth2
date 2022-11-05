package ars.spring.oauth2.domain.dao;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
import java.util.List;
import java.util.Set;

@Setter
@Getter
@Entity
@Table(name = "client")
@NoArgsConstructor
@AllArgsConstructor
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String idClient;

    private String clientSecret;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "client")
    private List<ClientDetails> details;

    @JsonIgnore
    @ManyToMany(mappedBy = "clients")
    private Set<User> users;
}
