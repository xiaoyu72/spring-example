package com.xiao.spring;

import com.xiao.spring6.User;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @Author XiaoYu
 * @Description 用户测试类
 * @Datetime 2023-01-31 18:26:55
 */
public class TestUser {

    @Test
    public void testUserObject(){
        // 加载Spring配置文件，对象创建
        ApplicationContext context = new ClassPathXmlApplicationContext("spring-bean.xml");

        // 获取创建的对象
        User user = (User) context.getBean("user");
        System.out.println(user);

        // 使用对象调用方法进行测试
        user.add();
    }

}
