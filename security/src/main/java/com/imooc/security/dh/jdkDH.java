package com.imooc.security.dh;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * @author QIN LI DA
 * @date 2018/11/29 15:03
 */
public class jdkDH {

    private static String src = "imooc security dh";

    public static void main(String[] args) {

        jdkDH();
    }

    public static void jdkDH() {
        try {
            /**
             * 1.初始化发送方密钥
             */
            KeyPairGenerator senderkeyPairGenerator = KeyPairGenerator.getInstance("DH");
            senderkeyPairGenerator.initialize(512);
            KeyPair senderKeyPair = senderkeyPairGenerator.generateKeyPair();
            //发送方公钥，发送给接收方（网络、文件。。。）
            byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();
            /**
             * 2.初始化接收方密钥
             */
            KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);
            PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);
            DHParameterSpec dhParameterSpec = ((DHPublicKey) receiverPublicKey).getParams();
            KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            receiverKeyPairGenerator.initialize(dhParameterSpec);
            KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
            PrivateKey receciverPrivateKey = receiverKeyPair.getPrivate();
            byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();
            /**
             * 3.密钥构建
             */
            KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
            receiverKeyAgreement.init(receciverPrivateKey);
            receiverKeyAgreement.doPhase(receiverPublicKey, true);
            SecretKey receiverDesKey = receiverKeyAgreement.generateSecret("DES");

            KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
            x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
            PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
            KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
            senderKeyAgreement.init(senderKeyPair.getPrivate());
            senderKeyAgreement.doPhase(senderPublicKey, true);

            SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
            if (Objects.equals(receiverDesKey, senderDesKey)) {
                System.out.println("双方密钥一致");
            }
            /**
             * 4.加密
             */
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk dh eccrypt:" + Base64.encodeBase64String(result));

            /**
             * 5.解密
             */
            cipher.init(Cipher.DECRYPT_MODE, senderDesKey);
            result = cipher.doFinal(result);
            System.out.println("jdk dh decrypt:" + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
