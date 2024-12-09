package UserService.ServiceImpls;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import UserService.Configurations.JwtUtil;
import UserService.DTOs.LoginRequestDto;
import UserService.DTOs.UserDTO;
import UserService.Entities.UserEntity;
import UserService.Enums.AccountStatus;
import UserService.Enums.MembershipType;
import UserService.Enums.Role;
import UserService.Enums.SubscriptionStatus;
import UserService.Exceptions.InvalidFileFormatException;
import UserService.Exceptions.UserNotFoundException;
import UserService.Helper.VerificationCodeGenerator;
import UserService.Repositories.UserRepository;
import UserService.Responses.LoginResponse;
import UserService.Services.MailService;
import UserService.Services.UserService;
import UserService.ValidationRequests.ImageValidationRequest;
import jakarta.validation.Valid;

@Service
public class UserServiceImpl implements UserService{

    private String baseUrl = "C:\\Users\\lenovo\\Desktop\\BookInventory\\ProfilePictures";
    private UserRepository userRepo;
    private MailService mailServ;
    private PasswordEncoder passwordEncoder;
    private JwtUtil jwtUtil;
    public UserServiceImpl(UserRepository userRepo, MailService mailServ,PasswordEncoder passwordEncoder,JwtUtil jwtUtil){
        this.userRepo = userRepo;
        this.mailServ = mailServ;
        this.passwordEncoder=passwordEncoder;
        this.jwtUtil=jwtUtil;
    }


    @Override
    public UserEntity createUser(UserEntity user, @Valid ImageValidationRequest profilePicture) throws IOException {
        String uid=UUID.randomUUID().toString().substring(0,10).replace('-', ' ');
        
        String userId = UUID.randomUUID().toString().substring(0, 10).replace("-", "");
        user.setId(userId);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setStatus(AccountStatus.ACTIVE);
        user.setEmailVerified(false);
        user.setPhoneNumberVerified(false);
        String token = UUID.randomUUID().toString().substring(0, 15).replace("\s", "");
        user.setVerificationToken(token);
       // String encryptedPassword=passwordEncoder.encode(bookUser.getPassword());
       // bookUser.setPassword(encryptedPassword);
        //logger.info(passwordEncoder.matches(bookUser.getPassword(), encryptedPassword)+"");
        // Set expiration time for the email verification token (24 hours from now)
        user.setEmailVerificationTokenExpirationTime(LocalDateTime.now().plusHours(24));
        user.setPhoneVerificationCodeExpirationTime(LocalDateTime.now().plusHours(24));

        user.setRole(Role.USER);
        user.setMembershipType(MembershipType.FREE);
        user.setSubscriptionStatus(SubscriptionStatus.NONE);

        if (profilePicture == null) {
            throw new InvalidFileFormatException("Profile Picture Should not be Empty...");
        } else {
            Path path = Paths.get(baseUrl, profilePicture.getOriginalFileName());
            Files.copy(profilePicture.getInputStream(), path);
            user.setProfilePicture(profilePicture.getOriginalFileName());
        }

        this.mailServ.sendVerificationMail(user.getEmail(), token);
        String verificationCode = VerificationCodeGenerator.generateVerificationCode();
        user.setPhoneVerificationCode(verificationCode);

        // Send SMS
        //this.smsServ.sendVerificationCode(bookUser.getPhoneNumber(), verificationCode);

        UserEntity users = userRepo.save(user);
        return users;
    }

    //verify user with token 
    @Override
    public UserEntity findUserByVerificationToken(String token) {
        UserEntity user = this.userRepo.findByVerificationToken(token)
                .orElseThrow(() -> new UserNotFoundException("Invalid Token...Please Enter a valid token to verify the user"));

        // Check if the token has expired
        if (user.getEmailVerificationTokenExpirationTime().isBefore(LocalDateTime.now())) {
            throw new UserNotFoundException("Token has expired. Please request a new verification email.");
        }

        user.setEmailVerified(true);
        user.setVerificationToken(null);
        return userRepo.save(user);
    }

    //resend User verification mail 

    @Override
    public UserEntity resendVerificationEmail(String userId) {
        UserEntity user = this.userRepo.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with the given ID"));

        // Check if the token has expired
        if (user.getEmailVerificationTokenExpirationTime().isBefore(LocalDateTime.now())) {
            // Token has expired, generate a new token
            String newToken = UUID.randomUUID().toString().substring(0, 15).replace("\s", "");
            user.setVerificationToken(newToken);

            // Set the new expiration time
            user.setEmailVerificationTokenExpirationTime(LocalDateTime.now().plusHours(24));

            // Send new verification email
            this.mailServ.sendVerificationMail(user.getEmail(), newToken);
        }

        return userRepo.save(user);
    }

   //Login user Service implementation
    @Override
    public LoginResponse LoginUser(LoginRequestDto userCredentials) {
        UserEntity findByEmail = userRepo.findByEmail(userCredentials.getEmail()).orElseThrow(()->new UserNotFoundException("User with Given Email Doesn't Exist...Please check the Email and try again"));
		if(!passwordEncoder.matches(userCredentials.getPassword(), findByEmail.getPassword())) {
			throw new UserNotFoundException("Please check your Password and try again");
		}
		String token=jwtUtil.generateToken(userCredentials.getEmail());
		return LoginResponse.builder().userEntity(findByEmail).token(token).build();
    }


    //find all users 
    @Override
    public List<UserDTO> findAllUsers() {
        List<UserEntity> allUsers = this.userRepo.findAll();
        List<UserDTO> allUserResponse = new ArrayList<>();

        if (allUsers != null || !allUsers.isEmpty()) {
            for (UserEntity user : allUsers) {
                UserDTO userDto = UserDTO.builder().id(user.getId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .fullName(user.getFullName())
                        .dateOfBirth(user.getDateOfBirth())
                        .phoneNumber(user.getPhoneNumber())
                        .isEmailVerified(user.isEmailVerified())
                        .isPhoneNumberVerified(user.isPhoneNumberVerified())
                        .role(user.getRole())
                        .status(user.getStatus())
                        .createdAt(user.getCreatedAt())
                        .updatedAt(user.getUpdatedAt())
                        .lastLogin(user.getLastLogin())
                        .profilePicture(user.getProfilePicture())
                        .profilePictureDownloadUrl(baseUrl + File.separator + user.getProfilePicture())
                        .address(user.getAddress())
                        .failedLoginAttempts(user.getFailedLoginAttempts())
                        .lockedUntill(user.getLockedUntill())
                        .isEmailVerified(user.isEmailVerified())
                        .isPhoneNumberVerified(user.isPhoneNumberVerified())
                        .membershipType(user.getMembershipType())
                        .subscriptionStatus(user.getSubscriptionStatus())
                        .subscriptionStart(user.getSubscriptionEnd())
                        .subscriptionEnd(user.getSubscriptionEnd())
                        .lastActivityAt(user.getLastActivityAt())
                        .bookmarkedBooks(user.getBookmarkedBooks())
                        .recentlyViewedBooks(user.getRecentlyViewedBooks())
                        .preferredGernes(user.getPreferredGernes())
                        .language(user.getLanguage()).build();
                allUserResponse.add(userDto);
            }
        }
        return allUserResponse;
    }

}
