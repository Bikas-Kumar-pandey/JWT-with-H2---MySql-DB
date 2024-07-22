package com.article.task21.controller;

import com.article.task21.dto.LoginRequest;
import com.article.task21.entity.Address;
import com.article.task21.dto.UserRequest;
import com.article.task21.dto.UserResponse;
import com.article.task21.jwtutil.JwtUtil;
import com.article.task21.service.MyUserDetailsService;
import com.article.task21.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PathVariable;
import java.util.List;

@RestController
public class UserController {

    private final UserService service;

    private final MyUserDetailsService myUserDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    public UserController(UserService service, MyUserDetailsService myUserDetailsService, JwtUtil jwtUtil) {
        this.service = service;
        this.myUserDetailsService = myUserDetailsService;
        this.jwtUtil = jwtUtil;
    }

    /*
     * This method is used to register the User.
     * It does not allow spring security to intercept in this endpoint coz we have asked SecurityConfig class to permit this register & authenticate endpoint.
     *
     * @param UserRequest user details requested
     * @return UserResponse user details responses
     * */
    @PostMapping("/user/register")
    public UserResponse register(@RequestBody UserRequest request) {
        return service.registerUser(request);
    }

    /*
     * This method is used to return the user  details by given id.
     * When we run this endpoint it will ask the token in the for of bearer automatically coz in SecurityConfig we did not permitted this endpoint to access freely

     * Curl to paste in postman to hit this endpoint
curl --location 'localhost:8080/user/1' \
--header 'Authorization: Bearer ~Token from authenticate endpoint~' \
--header 'Cookie: CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1'

     * @param id user id.
     * @return UserResponse User details response.
     * */
    @GetMapping("/user/{id}")
    public UserResponse getById(@PathVariable int id) {
        return service.getById(id);
    }

    @GetMapping("/user")
    public List<UserResponse> getAllUsers() {
        return service.getAllUsers();
    }

    /*
     * How JWT not allowing without token ?
     * when ever we do any call it will run JwtFilter.class which extends OncePerRequestFilter so it will filter and get the user details jwtUtils to fetch user name
     * from token, If it matches then only will proceed with this request
     *
     * @param address List of Address of the user.
     * @param id user id.
     * */
    @PostMapping("/user/{id}")
    public UserResponse addAddress(@RequestBody List<Address> address, @PathVariable int id) {
        return service.addAddress(address, id);
    }

    /*
     * This Method will generate a token based on user name.
     * first it will validate weather given username and password or valid or not from JWT in built class UsernamePasswordAuthenticationToken
     * AuthenticationManager it configured in SecurityConfig.class which set userDetails in its.
     *
     * if it valid then we will check that user is present in our DB or not
     * if user is present in DB then it will generate token
     *
     * @param LoginRequest = (username, password)
     * @returns Token
     * */
    @PostMapping("/authenticate")
    public String authenticate(@RequestBody LoginRequest request) {
        try {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
            authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid username/password");
        }
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(request.getUsername());
        return jwtUtil.generateToken(userDetails);
    }
}