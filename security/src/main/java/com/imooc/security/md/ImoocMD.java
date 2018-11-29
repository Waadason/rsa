package com.imooc.security.md;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @author QIN LI DA
 * @date 2018/11/29 10:25
 */
public class ImoocMD {

    private static String src = "imooc security md";

    public static void main(String[] args) {

        jdkMD5();
        jdkMD2();
        jdkMD4();
        jdkMD51();
        ccMD5();
        ccMD2();
    }


    public static void jdkMD5() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] md5bytes = md.digest(src.getBytes());
            System.out.println("jdk md5 :" + Hex.encodeHexString(md5bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void jdkMD2() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD2");
            byte[] md5bytes = md.digest(src.getBytes());
            System.out.println("jdk md5 :" + Hex.encodeHexString(md5bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void jdkMD51() {
        Digest digest = new MD5Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] md5Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md5Bytes, 0);
        System.out.println("jdk md5:" + new String(org.bouncycastle.util.encoders.Hex.encode(md5Bytes)));
    }

    public static void jdkMD4() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest md = MessageDigest.getInstance("MD4");
            byte[] md5bytes = md.digest(src.getBytes());
            System.out.println("jdk md4 :" + Hex.encodeHexString(md5bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }


//        Digest digest = new MD4Digest();
//        digest.update(src.getBytes(), 0, src.getBytes().length);
//        byte[] md4Bytes = new byte[digest.getDigestSize()];
//        digest.doFinal(md4Bytes, 0);
//        System.out.println("jdk md4:" + new String(org.bouncycastle.util.encoders.Hex.encode(md4Bytes)));
    }

    public static void ccMD5() {
        String ccmd5 = DigestUtils.md5Hex(src);
        System.out.println("ccmd5 md5" + ccmd5);
    }

    public static void ccMD2() {
        String ccmd2 = DigestUtils.md2Hex(src);
        System.out.println("ccmd2 md2" + ccmd2);
    }
}
