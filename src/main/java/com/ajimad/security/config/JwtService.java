package com.ajimad.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "6f3858b6c3637bed6190e1a895171b5a728777bb0a76c638ee30c519c5f02383";

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject); 
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
//      Function<Claims, T> claimsResolver: A functional interface that allows you to specify how to extract the specific claim(s)
//      you are interested in from the Claims object
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Generate JWT token with user details only
    public String generateToken(
            UserDetails userDetails
    ){
        // the HashMap class implement the Map interface so we can do down casting!
        return generateToken(new HashMap<>(), userDetails);
    }

    // Generate JWT token with claims and user details NOTE: we overload the generateToken method
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid (String token, UserDetails userDetails){
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date()); // make sure the token is expired before today's day.
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
