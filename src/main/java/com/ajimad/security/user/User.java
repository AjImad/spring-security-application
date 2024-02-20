package com.ajimad.security.user;

import com.ajimad.security.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

// NOTE: When Spring boot starts and set up the application it will use an object called user details,
// and this user details is an interface called userDetails interface

@Data // create getters and setter for us using lombok
@Builder // Builder design pattern allowing the same construction process to create different representation
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user") // class user already reserved by postresql, because psql has already a table called user
public class User implements UserDetails {
    @Id
    @SequenceGenerator(name = "user_sequence_gen", sequenceName = "user_sequence", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_sequence_gen")
    // default strategy is auto, hibernate will try to detect the best suitable option for us,
    // and because we're using PostreSQL it'll sequence strategy, if we're using MySQL it'll pick table, bcuz MySQL does not work with sequences.
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    // Enumerated is used to specify how an enum type is mapped to a database
    @Enumerated(EnumType.STRING) // with this approach, the enums values are stored as strings, where string value is the name of the enum as declared in the enum type.
    private Role role;

    @OneToMany(mappedBy = "user")
    private List<Token> tokens;

    // getAuthorities return a list of roles
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
