package com.xiao.spring6.iocxml.bean;

/**
 * @author XiaoYu
 * @description
 * @since 2023/2/1 7:51
 */
public class UserDaoImpl implements UserDao {
    @Override
    public void run() {
        System.out.println(this.getClass().getName() + " is run");
    }
}
