package com.article.task21.exception;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class GlobalException extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    protected ResponseEntity<?> handleUncaughtException(Exception e, WebRequest webRequest){
        Response response =new Response();
        response.setMessage(e.getMessage());
        response.setStatus("Bad request");
//        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        return handleExceptionInternal(e,response,new HttpHeaders(),HttpStatus.BAD_REQUEST,webRequest);
    }
}
