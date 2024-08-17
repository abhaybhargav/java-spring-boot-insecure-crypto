# Insecure Cryptographic Practices Demo

This Spring Boot application demonstrates the contrast between secure and insecure cryptographic practices in a simple user authentication system. It is designed for educational purposes to show how vulnerable cryptographic implementations can be exploited.

**WARNING**: This application intentionally implements insecure practices. Do not use this code in a production environment.

## Features

- User signup and login API
- Switchable secure (AES 256 GCM) and insecure (3DES ECB) encryption modes
- Logging of encrypted passwords (for demonstration purposes only)

## Prerequisites

- Docker

## Building and Running the Application

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/insecure-crypto-demo.git
   cd insecure-crypto-demo
   ```

2. Build the Docker image:
   ```
   docker build -t insecure-crypto-demo .
   ```

3. Run the container:
   ```
   docker run -p 8880:8880 -v $(pwd)/logs:/app/logs insecure-crypto-demo
   ```

The application will be accessible at `http://localhost:8880`.

## Interacting with the Application

### Signup

To create a new user:

```
curl -X POST -H "Content-Type: application/json" -d '{"username":"testuser","encryptedPassword":"mypassword"}' http://localhost:8880/api/users/signup
```

### Login

To log in with an existing user:

```
curl -X POST -H "Content-Type: application/json" -d '{"username":"testuser","encryptedPassword":"mypassword"}' http://localhost:8880/api/users/login
```

### Switching between Secure and Insecure Modes

The application uses the `crypto.mode` property in `application.properties` to determine which encryption mode to use. To switch between modes:

1. Stop the running container.
2. Edit the `application.properties` file:
   - For secure mode: `crypto.mode=secure`
   - For insecure mode: `crypto.mode=insecure`
3. Rebuild the Docker image and run the container again.

## Viewing Logs

To view the logs with encrypted passwords:

```
docker exec -it <container_id> cat /app/logs/application.log
```

Replace `<container_id>` with the ID of your running container.

**Note**: Logging passwords, even in encrypted form, is not a good practice in real-world applications. This is done here purely for demonstration purposes.

## Code Snippets

### Vulnerable (Insecure) Variant

```java
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
    return new String(decrypted, StandardCharsets.UTF_8);
}
```

This variant uses 3DES in ECB mode, which is vulnerable to various attacks.

### Secure Variant

```java
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
```

This variant uses AES in GCM mode, which provides both confidentiality and integrity.

## Security Considerations

This application is designed to demonstrate the dangers of insecure cryptographic practices. In a real-world scenario:

1. Never use insecure algorithms like 3DES in ECB mode.
2. Never log passwords, even in encrypted form.
3. Use strong, randomly generated keys and securely manage them.
4. Use authenticated encryption modes like GCM.
5. Implement proper error handling without revealing sensitive information.
6. Use secure password hashing algorithms (like bcrypt, scrypt, or Argon2) instead of encryption for storing passwords.