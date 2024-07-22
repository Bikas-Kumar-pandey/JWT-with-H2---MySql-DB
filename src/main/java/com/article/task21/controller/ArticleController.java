package com.article.task21.controller;

import com.article.task21.dto.ArticleReq;
import com.article.task21.dto.ArticleRes;
import com.article.task21.dto.CategoryResponse;
import com.article.task21.exception.Response;
import com.article.task21.service.ArticleService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class ArticleController {

    private final ArticleService articleService;

    public ArticleController(ArticleService articleService) {
        this.articleService = articleService;
    }

    @PostMapping("/article/{categoryId}")
    public CategoryResponse createArticle(@PathVariable int categoryId, @RequestBody ArticleReq req){
        return articleService.createArticle(categoryId,req);
    }

    @GetMapping("/article/{categoryId}")
    public CategoryResponse getAllArticles(@PathVariable int categoryId){
        return articleService.getAllArticle(categoryId);
    }

    @GetMapping("/article/{categoryId}/{articleId}")
    public CategoryResponse getArticleById(@PathVariable int categoryId,@PathVariable int articleId){
        return articleService.getArticleById(categoryId,articleId);
    }

    @PutMapping("/article/{categoryId}/{articleId}")
    public CategoryResponse updateArticle(@PathVariable int categoryId,@PathVariable int articleId,@RequestBody ArticleReq req){
        return articleService.updateArticle(categoryId,articleId,req);
    }

    @DeleteMapping("/article/{categoryId}/{articleId}")
    public Response deleteArticle(@PathVariable int categoryId, @PathVariable int articleId){
        return articleService.deleteArticle(categoryId,articleId);
    }

}
