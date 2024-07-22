package com.article.task21.service;


import com.article.task21.entity.Address;
import com.article.task21.entity.User;
import com.article.task21.dto.UserRequest;
import com.article.task21.dto.UserResponse;
import com.article.task21.exception.UserNotFound;
import com.article.task21.repo.UserRepo;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class UserService {

    public static final String AUTHORIZED = "Authorized";
    public static final String USER_NOT_FOUND = "User not present with id : ";
    public static final String UNAUTHORIZED = "Invalid username/password";
    public static final String MAIL_ALREADY_EXISTS = "Mail id already exists";
    public static final String MOBILE_ALREADY_EXISTS = "Mobile no: already exists";

    private final UserRepo userRepo;

    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepo userRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
    }

    public UserResponse registerUser(UserRequest request) {
        if (userRepo.existsByMobile(request.getMobile())) {
            throw new RuntimeException(MOBILE_ALREADY_EXISTS);
        }
        if (userRepo.existsByMail(request.getMail())) {
            throw new RuntimeException(MAIL_ALREADY_EXISTS);
        }

        User user = new User();
        user.setName(request.getName());
        user.setMail(request.getMail());
        user.setMobile(request.getMobile());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        User savedUser = userRepo.save(user);
        UserResponse userResponse = new UserResponse();
        userResponse.setId(savedUser.getId());
        userResponse.setName(savedUser.getName());
        userResponse.setMobile(savedUser.getMobile());
        userResponse.setMail(savedUser.getMail());
        List<Address> addresses = savedUser.getAddresses();
        List<String> addressResponse = new ArrayList<>();
        if (addresses != null) {
            for (Address address : addresses) {
                addressResponse.add(address.getAddress());
            }
            userResponse.setAddress(addressResponse);
        }
        return userResponse;
    }

    public UserResponse getById(int id) {
        Optional<User> byId = userRepo.findById(id);
        if (byId.isEmpty()) {
            throw new UserNotFound(USER_NOT_FOUND + id);
        }
        User user = byId.get();
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setName(user.getName());
        response.setMobile(user.getMobile());
        response.setMail(user.getMail());
        List<Address> addresses = user.getAddresses();
        List<String> addressResponse = new ArrayList<>();
        for (Address address : addresses) {
            addressResponse.add(address.getAddress());
        }
        response.setAddress(addressResponse);
        return response;
    }

    public List<UserResponse> getAllUsers() {
        List<User> allUsers = userRepo.findAll();
        List<UserResponse> userResponses = new ArrayList<>();
        for (User user : allUsers) {
            UserResponse response = new UserResponse();
            response.setId(user.getId());
            response.setName(user.getName());
            response.setMobile(user.getMobile());
            response.setMail(user.getMail());
            List<Address> addresses = user.getAddresses();
            List<String> addressResponse = new ArrayList<>();
            if (addresses != null) {
                for (Address address : addresses) {
                    addressResponse.add(address.getAddress());
                }
                response.setAddress(addressResponse);
            }
            userResponses.add(response);
        }
        return userResponses;
    }

    public UserResponse addAddress(List<Address> address, int id) {
        Optional<User> byId = userRepo.findById(id);
        if (byId.isEmpty()) {
            throw new UserNotFound(USER_NOT_FOUND + id);
        }
        User user = byId.get();
        List<Address> addresses = null;
        if (user.getAddresses() != null) {
            addresses = user.getAddresses();
        } else {
            addresses = new ArrayList<>();
        }

        addresses.addAll(address);

        user.setAddresses(addresses);
        User savedUser = userRepo.save(user);
        UserResponse userResponse = new UserResponse();
        userResponse.setId(savedUser.getId());
        userResponse.setName(savedUser.getName());
        userResponse.setMobile(savedUser.getMobile());
        userResponse.setMail(savedUser.getMail());
        List<Address> addressesSaved = savedUser.getAddresses();
        List<String> addressResponse = new ArrayList<>();
        for (Address i : addressesSaved) {
            addressResponse.add(i.getAddress());
        }
        userResponse.setAddress(addressResponse);

        return userResponse;
    }
}
