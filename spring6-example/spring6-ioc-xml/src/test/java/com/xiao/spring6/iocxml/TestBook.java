package com.xiao.spring6.iocxml;

import com.xiao.spring6.iocxml.bean.UserDao;
import com.xiao.spring6.iocxml.di.Book;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author XiaoYu
 * @description
 * @since 2023/2/1 8:06
 */
public class TestBook {
    private ApplicationContext context;

    @BeforeEach
    void initApplicationContext() {
        context = new ClassPathXmlApplicationContext("spring-bean.xml");
    }

    @Test
    void testDIBySetter() {
        Book book = context.getBean("bookOne", Book.class);
        System.out.println(book);
    }
    @Test
    void testDIByConstructor() {
        Book book = context.getBean("bookTwo", Book.class);
        System.out.println(book);
    }
}
