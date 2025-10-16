package sw.skuniv.travelplanner.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import sw.skuniv.travelplanner.DI.dto.UserDTO;

import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {
    private final Key key;
    private final long accessTokenExpTime;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public JwtUtil(
            @Value("${jwt.secret}")
            String secretKey,

            @Value("${jwt.expiration_time}")
            long accessTokenExpTime
    ) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpTime = accessTokenExpTime;
    }

    //call, userDTO와 accessTokenExpTime(만료시간)울 토대로 JWT생성
    public String createAccessToken(UserDTO userDTO) {
        return createToken(userDTO, accessTokenExpTime);
    }



    //실질적인 JWT토큰 생성 메소드
    private String createToken(UserDTO userDTO, long expireTime) {
        Claims claims = Jwts.claims(); //Claims 객체 생성

        //claims 객체에 사용자 정보 저장
        claims.put("memberId", userDTO.getId());
        claims.put("email", userDTO.getEmail());

        //JWT 발행시간 및 만료시간 설정
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime tokenValidity = now.plusSeconds(expireTime);


        logger.info("JwtUtil class pass");

        //사용자 정보와 만료시각등을 설정하고 HMAC-SHA256 algorithm을 사용하여 비밀키로 서명 추가
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(now.toInstant()))
                .setExpiration(Date.from(tokenValidity.toInstant()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    //주어진 JWT에서 memberId정보를 추출하는 메소드로 parseClaims를 이용하여 토큰의 정보를 분석한 후 memberId 추출
    public Long getUserId(String token) {
        return parseClaims(token).get("memberId", Long.class);
    }

    public String getUserEmail(String token){
        return parseClaims(token).get("email", String.class);
    }


    //JWT 토큰이 유효한지 검증으로 토큰을 파싱할 때 발생할 수 있는 다양한 예외를 처리하여 토큰이 유효한지 여부를 확인
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) { //토큰이 변조되었거나 형식이 잘못된 경우
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) { //토큰이 만료된 경우
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) { //지원하지 않는 토큰 형식인 경우
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) { //토큰의 내용이 비어있는 경우
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }


    //주어진 JWT 토큰을 파싱하여 그 안에 포함된 claims(토큰에 담긴 정보)를 반환하는 메소드
    //만약 토큰이 만료되었더라도 만료된 claims를 반환하여 토큰에 담긴 정보를 사용할 수 있음
    public Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
