package com.xiao.spring;

import com.xiao.spring6.User;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.lang.reflect.InvocationTargetException;

/**
 * @Author XiaoYu
 * @Description 用户测试类
 * @Datetime 2023-01-31 18:26:55
 */
public class TestUser {

    private Logger logger = LoggerFactory.getLogger(TestUser.class);

    @Test
    public void testUserObject(){
        // 加载Spring配置文件，对象创建
        ApplicationContext context = new ClassPathXmlApplicationContext("spring-bean.xml");

        // 获取创建的对象
        User user = (User) context.getBean("user");
        System.out.println(user);

        // 使用对象调用方法进行测试
        user.add();

        // 手动写入日志
        logger.info("======执行调用结束======");
    }

    @Test
    public void testReflection() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        // 通过反射机制调用无参数构造方法创建对象
        Class clazz = Class.forName("com.xiao.spring6.User");
        //Object obj = clazz.newInstance();
        User user = (User) clazz.getDeclaredConstructor().newInstance();
        System.out.println(user);
    }
}
