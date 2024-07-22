package com.article.task21.repo;

import com.article.task21.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CategoryRepo extends JpaRepository<Category,Integer> {

    boolean existsByCategoryName(String categoryName);
}
