package com.article.task21.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.sql.Timestamp;

@Data
public class ArticleRes {
    private int id;
    private String title;
    private Timestamp time;
    private String location;
    private String description;
}
