package UserService.Services;

import java.io.IOException;
import java.util.List;

import UserService.DTOs.LoginRequestDto;
import UserService.DTOs.UserDTO;
import UserService.Entities.UserEntity;
import UserService.Responses.LoginResponse;
import UserService.ValidationRequests.ImageValidationRequest;
import jakarta.validation.Valid;

public interface UserService {

    UserEntity createUser(UserEntity user,@Valid ImageValidationRequest profilePicture) throws IOException;
    UserEntity findUserByVerificationToken(String token);
    UserEntity resendVerificationEmail(String userId);
    LoginResponse LoginUser(LoginRequestDto userCredentials);
    List<UserDTO> findAllUsers();
}
