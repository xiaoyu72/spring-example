package com.xiao.spring6.iocxml;

import com.xiao.spring6.iocxml.bean.UserDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author XiaoYu
 * @description
 * @since 2023/2/1 7:53
 */
public class TestUserDao {

    private ApplicationContext context;

    @BeforeEach
    void initApplicationContext() {
        context = new ClassPathXmlApplicationContext("spring-bean.xml");
    }

    @Test
    void testGetBeanObjectByType() {
        UserDao userDao = context.getBean(UserDao.class);
        System.out.println(userDao);
        userDao.run();
    }
}
