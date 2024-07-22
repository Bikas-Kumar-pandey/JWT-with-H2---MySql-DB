package com.article.task21.controller;

import com.article.task21.dto.CategoryReq;
import com.article.task21.entity.Category;
import com.article.task21.exception.Response;
import com.article.task21.service.CategoryService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class CategoryController {

    private final CategoryService service;

    public CategoryController(CategoryService service) {
        this.service = service;
    }

    @PostMapping("/category")
    public Category createCategory(@RequestBody CategoryReq req){
        return service.createCategory(req);
    }

    @GetMapping("/category/{id}")
    public Category getById(@PathVariable int id){
        return service.getOneById(id);
    }

    @GetMapping("/category")
    public List<Category> getAllCategory(){
        return service.getAll();
    }

    @PutMapping("/category/{id}")
    public Category updateCategory(@PathVariable int id,@RequestBody CategoryReq req){
        return service.updateCategory(id,req);
    }

    @DeleteMapping("/category/{id}")
    public Response deleteCategory(@PathVariable int id){
        return service.deleteCategory(id);
    }

}
