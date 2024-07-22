package com.article.task21.service;

import com.article.task21.dto.ArticleReq;
import com.article.task21.dto.ArticleRes;
import com.article.task21.dto.CategoryResponse;
import com.article.task21.entity.Article;
import com.article.task21.entity.Category;
import com.article.task21.exception.Response;
import com.article.task21.repo.ArticleRepo;
import com.article.task21.repo.CategoryRepo;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ArticleService {

    private final ArticleRepo articleRepo;

    private final CategoryRepo categoryRepo;

    public ArticleService(ArticleRepo articleRepo, CategoryRepo categoryRepo) {
        this.articleRepo = articleRepo;
        this.categoryRepo = categoryRepo;
    }

    public CategoryResponse createArticle(int categoryId, ArticleReq req){
        if(!categoryRepo.existsById(categoryId)){
            throw new RuntimeException("Category not found with id : "+categoryId);
        }

        Category category = categoryRepo.findById(categoryId).get();

        Article article=new Article();
        article.setTitle(req.getTitle());
        article.setLocation(req.getLocation());
        article.setTime(req.getTime());
        article.setDescription(req.getDescription());
        article.setCategoryId(categoryId);

        Article save = articleRepo.save(article);

        ArticleRes articleRes = entityToDto(save);

        CategoryResponse response=new CategoryResponse();
        response.setCategoryId(categoryId);
        response.setCategory(category.getCategoryName());

        List<ArticleRes> articleResList=new ArrayList<>();
        articleResList.add(articleRes);
        response.setArticles(articleResList);


        return response;

    }

    public CategoryResponse getArticleById(int categoryId,int articleId){
        if(!categoryRepo.existsById(categoryId)){
            throw new RuntimeException("Category not found with id : "+categoryId);
        }
        if(!articleRepo.existsById(articleId)){
            throw new RuntimeException("Article not found with id : "+articleId);
        }
        Article article = articleRepo.findById(articleId).get();
        Category category = categoryRepo.findById(categoryId).get();

        ArticleRes articleRes = entityToDto(article);

        CategoryResponse response=new CategoryResponse();
        response.setCategoryId(categoryId);
        response.setCategory(category.getCategoryName());

        List<ArticleRes> articleResList=new ArrayList<>();
        articleResList.add(articleRes);
        response.setArticles(articleResList);

        return response;
    }


    public CategoryResponse getAllArticle(int categoryId){
        if(!categoryRepo.existsById(categoryId)){
            throw new RuntimeException("Category not found with id : "+categoryId);
        }
        List<Article> articles=articleRepo.findByCategoryId(categoryId);
        Category category = categoryRepo.findById(categoryId).get();

        List<ArticleRes> articleResList=new ArrayList<>();

        for(Article article:articles){
            ArticleRes res = entityToDto(article);
            articleResList.add(res);
        }

        CategoryResponse response=new CategoryResponse();

        response.setCategoryId(categoryId);
        response.setCategory(category.getCategoryName());
        response.setArticles(articleResList);


        return response;
    }

    public CategoryResponse updateArticle(int categoryId,int articleId,ArticleReq req){
        if(!categoryRepo.existsById(categoryId)){
            throw new RuntimeException("Category not found with id : "+categoryId);
        }
        if(!articleRepo.existsById(articleId)){
            throw new RuntimeException("Article not found with id : "+articleId);
        }
        Article article = articleRepo.findById(articleId).get();
        Category category = categoryRepo.findById(categoryId).get();

        article.setTitle(req.getTitle());
        article.setDescription(req.getDescription());
        article.setTime(req.getTime());
        article.setLocation(req.getLocation());

        Article save = articleRepo.save(article);

        ArticleRes articleRes = entityToDto(save);

        CategoryResponse response=new CategoryResponse();
        response.setCategoryId(categoryId);
        response.setCategory(category.getCategoryName());

        List<ArticleRes> articleResList=new ArrayList<>();
        articleResList.add(articleRes);
        response.setArticles(articleResList);

        return response;

    }


    public Response deleteArticle(int categoryId, int articleId){
        if(!categoryRepo.existsById(categoryId)){
            throw new RuntimeException("Category not found with id : "+categoryId);
        }
        if(!articleRepo.existsById(articleId)){
            throw new RuntimeException("Article not found with id : "+articleId);
        }
        Article article = articleRepo.findById(articleId).get();
        articleRepo.delete(article);

        Response response=new Response();
        response.setStatus("ok");
        response.setMessage("Article deleted with id : "+articleId);

        return response;
    }


    private ArticleRes entityToDto(Article article){
        ArticleRes res=new ArticleRes();
        res.setId(article.getId());
        res.setTitle(article.getTitle());
        res.setLocation(article.getLocation());
        res.setDescription(article.getDescription());
        res.setTime(article.getTime());
        return res;
    }

}