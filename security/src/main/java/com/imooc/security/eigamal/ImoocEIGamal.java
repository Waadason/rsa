package com.imooc.security.eigamal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.DHParameterSpec;
import java.security.*;

/**
 * @author QIN LI DA
 * @date 2018/11/29 17:45
 */
public class ImoocEIGamal {

    private static String src = "imooc security EIGamal";

    public static void main(String[] args) {

        EIGamaltest();
    }

    public static void EIGamaltest() {
        try {
            //公钥加密，私钥解密
            Security.addProvider(new BouncyCastleProvider());

            //初始化密钥
            AlgorithmParameterGenerator algorithmParameterGenerator =
                    AlgorithmParameterGenerator.getInstance("EIGamal");
            algorithmParameterGenerator.init(256);
            AlgorithmParameters algorithmParameters =
                    algorithmParameterGenerator.generateParameters();
            DHParameterSpec dhParameterSpec = (DHParameterSpec)
                    algorithmParameters.getParameterSpec(DHParameterSpec.class);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EIGamal");
            keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey elGamalPublicKey = keyPair.getPublic();
            PrivateKey elGamalPrivateKey = keyPair.getPrivate();
            System.out.println("public Key:" + Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
            System.out.println("private Key:" + Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
