package com.example.aesrsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Map;
import jakarta.annotation.PostConstruct;

@RestController
@RequestMapping("/api")
public class CryptoController {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // AES加密
    @PostMapping("/aes/encrypt")
    public ResponseEntity<String> aesEncrypt(@RequestBody Map<String, String> payload) {
        try {
            String text = payload.get("text");
            String key = payload.get("key");
            String mode = payload.get("mode");
            String iv = payload.get("iv");

            if (key == null || key.length() != 16) {
                return ResponseEntity.badRequest().body("AES密钥必须为16字节");
            }

            String algorithm = "AES/" + mode + "/PKCS7Padding";
            Cipher cipher = Cipher.getInstance(algorithm);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            if ("CBC".equalsIgnoreCase(mode)) {
                if (iv == null || iv.length() != 16) {
                    return ResponseEntity.badRequest().body("CBC模式需要16字节的偏移量");
                }
                IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }

            byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            return ResponseEntity.ok(Base64.getEncoder().encodeToString(encrypted));
        } catch (Exception e) {
            return ResponseEntity.status(500).body("AES加密出错: " + e.getMessage());
        }
    }

    // AES解密
    @PostMapping("/aes/decrypt")
    public ResponseEntity<String> aesDecrypt(@RequestBody Map<String, String> payload) {
        try {
            String text = payload.get("text");
            String key = payload.get("key");
            String mode = payload.get("mode");
            String iv = payload.get("iv");

            if (key == null || key.length() != 16) {
                return ResponseEntity.badRequest().body("AES密钥必须为16字节");
            }

            String algorithm = "AES/" + mode + "/PKCS7Padding";
            Cipher cipher = Cipher.getInstance(algorithm);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            if ("CBC".equalsIgnoreCase(mode)) {
                if (iv == null || iv.length() != 16) {
                    return ResponseEntity.badRequest().body("CBC模式需要16字节的偏移量");
                }
                IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            }

            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(text));
            return ResponseEntity.ok(new String(decrypted, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return ResponseEntity.status(500).body("AES解密出错: " + e.getMessage());
        }
    }

    // RSA
    private static KeyPair rsaKeyPair;

    //生成密钥对
    @PostConstruct
    public void initRSA() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
    }

    //RSA加密
    @PostMapping("/rsa/encrypt")
    public ResponseEntity<String> rsaEncrypt(@RequestBody Map<String, String> payload) {
        try {
            String text = payload.get("text");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
            byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
            return ResponseEntity.ok(encryptedBase64);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("RSA加密出错: " + e.getMessage());
        }
    }

    //RSA解密
    @PostMapping("/rsa/decrypt")
    public ResponseEntity<String> rsaDecrypt(@RequestBody Map<String, String> payload) {
        try {
            String text = payload.get("text");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            byte[] decoded = Base64.getDecoder().decode(text);
            byte[] decrypted = cipher.doFinal(decoded);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            return ResponseEntity.ok(decryptedText);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("RSA解密出错: " + e.getMessage());
        }
    }
}

