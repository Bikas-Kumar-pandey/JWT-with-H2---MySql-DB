package com.article.task21.dto;

import lombok.Data;

import java.util.List;

@Data
public class UserResponse {
    private int id;
    private String name;
    private String mobile;
    private String mail;
    private List<String> address;
}
