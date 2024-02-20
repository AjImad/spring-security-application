package com.ajimad.security.token;

import com.ajimad.security.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Token {

    @Id
    @SequenceGenerator(name = "tokenId_seq_generator", sequenceName = "tokenId_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "tokenId_seq_generator")
    private Integer id;
    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;
    private boolean expired;
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
