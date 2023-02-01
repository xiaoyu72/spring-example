package com.xiao.spring6.iocxml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author XiaoYu
 * @description
 * @since 2023/2/1 7:35
 */
public class TestUser {

    private ApplicationContext context;

    @BeforeEach
    void initApplicationContext() {
        context = new ClassPathXmlApplicationContext("spring-bean.xml");

    }

    @Test
    void testGetBeanObjectById() {
        User user = (User) context.getBean("user");
        System.out.println("根据ID获取Bean: " + user);
    }

    @Test
    void testGetBeanObjectByType() {
        User user = context.getBean(User.class);
        System.out.println("根据类型获取Bean: " + user);
    }

    @Test
    void testGetBeanObjectByIdAndType() {
        User user = context.getBean("user", User.class);
        System.out.println("根据ID和类型获取Bean: " + user);
    }
}
