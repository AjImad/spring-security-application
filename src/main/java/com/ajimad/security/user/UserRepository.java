package com.ajimad.security.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    // SELECT * (ALL THE COLUMNS) FROM _user WHERE email = ? => this query executed by findUserByEmail method.
    Optional<User> findUserByEmail(String email);
}
