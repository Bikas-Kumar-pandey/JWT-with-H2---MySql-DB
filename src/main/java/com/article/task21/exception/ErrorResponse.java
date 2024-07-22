package com.article.task21.exception;

import lombok.Data;

@Data
public class ErrorResponse {
    private String status;
    private String errorMessage;
}
