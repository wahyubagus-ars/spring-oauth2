package ars.spring.oauth2.domain.dao;

import lombok.*;

import javax.persistence.*;
import java.util.List;

@Setter
@Getter
@Entity
@Table(name = "client")
@NoArgsConstructor
@AllArgsConstructor
public class Client {

    @Id
    private String clientId;

    private String clientSecret;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "client")
    private List<ClientDetails> details;

}
