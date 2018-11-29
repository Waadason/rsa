package com.imooc.security.sha;


import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @author QIN LI DA
 * @date 2018/11/29 11:14
 */
public class ImoocSHA {

    private static String src = "imooc seurity sha";

    public static void main(String[] args) {
        jdkSHA1();
        bcSHA1();
        bcSHA224();
        bcSHA224_2();
        ccSHA1();
    }

    public static void jdkSHA1() {

        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            md.update(src.getBytes());
            System.out.println("jdk sha-1" + Hex.encodeHexString(md.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bcSHA1() {
        Digest digest = new SHA1Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] sha1Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha1Bytes, 0);
        System.out.println("bc sha-1:" + new String(org.bouncycastle.util.encoders.Hex.encode(sha1Bytes)));
    }

    public static void bcSHA224() {
        Digest digest = new SHA224Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] sha224Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha224Bytes, 0);
        System.out.println("bc sha-224:" + new String(org.bouncycastle.util.encoders.Hex.encode(sha224Bytes)));
    }

    public static void bcSHA224_2() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest md = MessageDigest.getInstance("SHA224");
            byte[] sha224_2bytes = md.digest(src.getBytes());
            System.out.println("jdk SHA224_2 :" + Hex.encodeHexString(sha224_2bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void ccSHA1() {
        System.out.println("cc sha1:" + DigestUtils.sha1Hex(src.getBytes()));
        System.out.println("cc sha1:" + DigestUtils.sha1Hex(src));
    }
}
