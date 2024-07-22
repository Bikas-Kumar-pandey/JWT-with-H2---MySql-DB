package com.article.task21.dto;

import lombok.Data;

import java.util.List;

@Data
public class CategoryResponse {
    private int categoryId;
    private String category;
    private List<ArticleRes> articles;
}
