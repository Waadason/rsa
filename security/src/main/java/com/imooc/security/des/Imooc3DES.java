package com.imooc.security.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * @author QIN LI DA
 * @date 2018/11/28 15:28
 */
public class Imooc3DES {

    private static String src = "imooc security 3des";

    public static void main(String[] args) {

        jdk3DES();
        BC3DES();
    }

    /**
     * jdk
     */
    private static void jdk3DES() {

        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
//            keyGenerator.init(168);
            //随机生成一定长度
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            //key转换
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            SecretKey converSecretKey = factory.generateSecret(desKeySpec);

            //加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk 3DES encrypt:" + Hex.encodeHexString(result));

            //解密
            cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
            result = cipher.doFinal(result);
            System.out.println("jdk 3DES decrypt:" + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void BC3DES() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede", "BC");
            keyGenerator.getProvider();
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            //key转换
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            SecretKey converSecretKey = factory.generateSecret(desKeySpec);

            //加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("bc 3des encrypt:" + Hex.encodeHexString(result));

            //解密
            cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
            result = cipher.doFinal(result);
            System.out.println("bc 3des decrypt:" + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
