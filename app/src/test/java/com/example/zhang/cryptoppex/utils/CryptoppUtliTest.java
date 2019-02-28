package com.example.zhang.cryptoppex.utils;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by Administrator on 2018/12/3.
 */
public class CryptoppUtliTest {
    @Test
    public void genAESKeyPair() throws Exception {
        System.out.println(CryptoppUtli.genAESKeyPair());
    }

}