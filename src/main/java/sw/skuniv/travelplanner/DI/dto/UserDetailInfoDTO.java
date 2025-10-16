package sw.skuniv.travelplanner.DI.dto;

import lombok.Data;


/*
구글 로그인 이후 닉네임 추가 정보를 입력받을 때 사용
*/

@Data
public class UserDetailInfoDTO {
    private String email;
    private String nickname;
}
