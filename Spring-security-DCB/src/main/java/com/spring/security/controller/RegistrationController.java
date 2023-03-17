package com.spring.security.controller;

import com.spring.security.entity.User;
import com.spring.security.entity.VerificationToken;
import com.spring.security.event.RegistrationCompleteEvent;
import com.spring.security.model.PasswordModel;
import com.spring.security.model.UserModel;
import com.spring.security.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RestController
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private ApplicationEventPublisher publisher;

    @GetMapping("/hello")
    public String helloApp() {
        System.out.println("hello app called");

        return "hello app";
    }

    @PostMapping("/register")
    public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request) {

        User user = userService.registerUser(userModel);
        publisher.publishEvent(
                new RegistrationCompleteEvent(user, applicationUrl(request)));
        return "Success";
    }

    @GetMapping("/verifyRegistration")
    public String verifyRegistration(@RequestParam("token") String token) {

        String result = userService.validateVerificationToken(token);
        if (result.equalsIgnoreCase("valid"))
            return "User verified successfully";
        else
            return "Bad User";
    }

    @GetMapping("/resendVerificationToken")
    public String resendVerificationToken(@RequestParam("token") String oldToken,
                                          HttpServletRequest request) {

        VerificationToken verificationToken = userService.generateNewVerificationToken(oldToken);

        User user = verificationToken.getUser();

        resendVerificationMail(user, applicationUrl(request), verificationToken);

        return "Verification link sent";

    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestBody PasswordModel passwordModel, HttpServletRequest request) {

        User user = userService.findUserByEmail(passwordModel.getEmail());

        String url = "";

        if (user != null) {
            String token = UUID.randomUUID().toString();
            userService.createPasswordResetTokenForUser(user, token);
            url = passwordResetTokenMail(user, applicationUrl(request), token);
        }

        return url;
    }

    @PostMapping("/savePassword")
    public String savePassword(@RequestParam("token") String token,
                               @RequestBody PasswordModel passwordModel) {

        String result = userService.validatePasswordResetToken(token);

        if (!result.equalsIgnoreCase("valid"))
            return "Invalid Token";

        Optional<User> user = userService.getUserByPasswordResetToken(token);
        if (user.isPresent()) {
            userService.changePassword(user.get(), passwordModel.getNewPassword());
            return "Password reset successful";

        } else {
            return "Invalid Token";
        }

    }

    @PostMapping("/changePassword")
    public String changePassword(@RequestBody PasswordModel passwordModel) {

        User user = userService.findUserByEmail(passwordModel.getEmail());
        if (!userService.checkIfValidOldPassword(user, passwordModel.getOldPassword())) {
            return "invalid old password";
        }

        //Save new password
        userService.changePassword(user, passwordModel.getNewPassword());

        return "Password change successfully";

    }

    private String passwordResetTokenMail(User user, String applicationUrl, String token) {

        String url = applicationUrl
                + "/savePassword?token="
                + token;
        //send verification method
        log.info("Click link to verify your account:{}", url);
        return url;
    }

    private void resendVerificationMail(User user, String applicationUrl, VerificationToken verificationToken) {

        String url = applicationUrl
                + "/verifyRegistration?token="
                + verificationToken.getToken();
        //send verification method
        log.info("Click link to verify your account:{}", url);
    }

    private String applicationUrl(HttpServletRequest request) {

        return "http://" + request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();
    }
}
