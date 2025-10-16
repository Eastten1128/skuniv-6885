package sw.skuniv.travelplanner.DI.dto;

import lombok.*;
import sw.skuniv.travelplanner.DI.entity.User;

/*
구글 로그인 시 사용
*/
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {
    private Long id;
    private String email;
    private String password;
    private String name;
    private String userImg;
    private String preferredGenre;

    public User toEntity(){
        return User.builder()
                .email(email)
                .password(password)
                .name(name)
                .build();
    }
}
