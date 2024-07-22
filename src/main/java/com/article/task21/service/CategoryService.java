package com.article.task21.service;

import com.article.task21.dto.CategoryReq;
import com.article.task21.entity.Category;
import com.article.task21.exception.Response;
import com.article.task21.repo.CategoryRepo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class CategoryService {
    private final CategoryRepo categoryRepo;

    public CategoryService(CategoryRepo categoryRepo) {
        this.categoryRepo = categoryRepo;
    }

   public Category createCategory(CategoryReq req){
        Category category=new Category();
        if(categoryRepo.existsByCategoryName(req.getCategoryName())){
            throw new RuntimeException("Duplicate category name");
        }
        category.setCategoryName(req.getCategoryName());
       return categoryRepo.save(category);
   }

   public Category getOneById(int id){
       Optional<Category> byId = categoryRepo.findById(id);
       if(byId.isEmpty()){
           throw new RuntimeException("Category not found with id : "+id);
       }
       return byId.get();
   }

    public List<Category> getAll(){
        return categoryRepo.findAll();
    }

    public Category updateCategory(int id,CategoryReq req){
        Optional<Category> byId = categoryRepo.findById(id);
        if(byId.isEmpty()){
            throw new RuntimeException("Category not found with id : "+id);
        }
        Category category = byId.get();
        category.setCategoryName(req.getCategoryName());
        return categoryRepo.save(category);
    }

    public Response deleteCategory(int id){
        Optional<Category> byId = categoryRepo.findById(id);
        if(byId.isEmpty()){
            throw new RuntimeException("Category not found with id : "+id);
        }
        Category category = byId.get();
        categoryRepo.delete(category);
        Response response=new Response();
        response.setStatus("ok");
        response.setMessage("Category with id : "+id+" deleted");
        return response;
    }


}
