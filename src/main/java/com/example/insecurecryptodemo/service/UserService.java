package com.example.insecurecryptodemo.service;

import com.example.insecurecryptodemo.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private static final String INSECURE_ALGO = "DESede/ECB/PKCS5Padding";
    private static final String SECURE_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    @Value("${crypto.mode}")
    private String cryptoMode;

    private final Map<String, User> users = new HashMap<>();
    private SecretKey secureKey;
    private SecretKey insecureKey;

    public UserService() throws Exception {
        // Generate keys for both secure and insecure modes
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        this.secureKey = keyGen.generateKey();

        keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(168);
        this.insecureKey = keyGen.generateKey();
    }

    public void signup(User user) throws Exception {
        String encryptedPassword = encryptPassword(user.getEncryptedPassword());
        user.setEncryptedPassword(encryptedPassword);
        users.put(user.getUsername(), user);
        logger.info("User signed up: {} (Encryption mode: {})", user.getUsername(), cryptoMode);
        // Note: In a production environment, we should not log sensitive information
        logger.debug("Encrypted password for user {}: {}", user.getUsername(), encryptedPassword);
    }

    public boolean login(User user) throws Exception {
        User storedUser = users.get(user.getUsername());
        if (storedUser != null) {
            String storedEncryptedPassword = storedUser.getEncryptedPassword();
            String inputPassword = user.getEncryptedPassword();
            
            // Check if the input is already encrypted
            String decryptedInputPassword;
            try {
                decryptedInputPassword = decryptPassword(inputPassword);
            } catch (Exception e) {
                // If decryption fails, assume the input is a plain password
                decryptedInputPassword = inputPassword;
            }
            
            String decryptedStoredPassword = decryptPassword(storedEncryptedPassword);
            
            logger.info("Login attempt for user: {} (Encryption mode: {})", user.getUsername(), cryptoMode);
            logger.info("Stored encrypted password for user {}: {}", user.getUsername(), storedEncryptedPassword);
            
            boolean isAuthenticated = decryptedStoredPassword.equals(decryptedInputPassword);
            logger.info("Login result for user {}: {}", user.getUsername(), isAuthenticated ? "Success" : "Failure");
            return isAuthenticated;
        }
        logger.info("Login attempt failed: User {} not found", user.getUsername());
        return false;
    }

    private String encryptPassword(String password) throws Exception {
        String encryptedPassword;
        if ("insecure".equals(cryptoMode)) {
            encryptedPassword = insecureEncrypt(password);
            logger.info("Password encrypted using insecure method (3DES ECB)");
        } else {
            encryptedPassword = secureEncrypt(password);
            logger.info("Password encrypted using secure method (AES 256 GCM)");
        }
        return encryptedPassword;
    }

    private String decryptPassword(String encryptedPassword) throws Exception {
        if ("insecure".equals(cryptoMode)) {
            logger.info("Decrypting password using insecure method (3DES ECB)");
            return insecureDecrypt(encryptedPassword);
        } else {
            logger.info("Decrypting password using secure method (AES 256 GCM)");
            return secureDecrypt(encryptedPassword);
        }
    }

    private String insecureEncrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(INSECURE_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, insecureKey);
        byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String insecureDecrypt(String encryptedInput) throws Exception {
        Cipher cipher = Cipher.getInstance(INSECURE_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, insecureKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedInput));
        return new String(decrypted, StandardCharsets.UTF_8).trim();
    }

    private String secureEncrypt(String input) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        Cipher cipher = Cipher.getInstance(SECURE_ALGO);
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secureKey, ivSpec);
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        byte[] encrypted = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(cipherText, 0, encrypted, iv.length, cipherText.length);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String secureDecrypt(String encryptedInput) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(encryptedInput);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encrypted, 0, iv, 0, iv.length);
        Cipher cipher = Cipher.getInstance(SECURE_ALGO);
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secureKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted, GCM_IV_LENGTH, encrypted.length - GCM_IV_LENGTH);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}