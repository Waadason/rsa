package com.imooc.security.hmac;


import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author QIN LI DA
 * @date 2018/11/29 13:59
 */
public class ImoocHmac {

    private static String src = "imooc security hmac";

    public static void main(String[] args) {

        jdkHmacMD5();
        bcHmacMD5();
    }

    public static void jdkHmacMD5() {
        try {
            //初始化KeyGenerator
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
            //产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            //获得密钥
//            byte[] key = secretKey.getEncoded();
            byte[] key = Hex.decodeHex(new char[]{'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'});
            //还原密钥
            SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5");
            //实例化MAC
            Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm());
            //初始化MAC
            mac.init(restoreSecretKey);
            byte[] hmacMD5Bytes = mac.doFinal(src.getBytes());
            System.out.println("jdk hmacMD5:" + Hex.encodeHexString(hmacMD5Bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcHmacMD5() {
        HMac hmac = new HMac(new MD5Digest());
        hmac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
        hmac.update(src.getBytes(), 0, src.getBytes().length);

        byte[] hmacMD5Bytes = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacMD5Bytes, 0);

        System.out.println("bc hmacMD5:" + new String(org.bouncycastle.util.encoders.Hex.encode(hmacMD5Bytes)));
    }
}
