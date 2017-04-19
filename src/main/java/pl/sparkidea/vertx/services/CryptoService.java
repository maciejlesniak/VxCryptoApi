package pl.sparkidea.vertx.services;

import java.util.Optional;

/**
 * Encrypt / decrypt interface
 * @author Maciej Lesniak / Spark Media
 * @version 19/04/2017
 */
public interface CryptoService {

    /**
     * Gets plain message bytes from input and returns encrypted ones
     * @param plainMessage unencrypted message
     * @return encrypted message
     */
    byte[] encrypt(byte[] plainMessage);

    /**
     * Gets encrypted bytes from input and returns decrypted message
     * @param encryptedMessage encrypted message
     * @return decrypted message
     */
    byte[] decrypt(byte[] encryptedMessage);

    /**
     * Encrypt string-based message and return Base64-encoded string
     * @param plainMessage plain message
     * @return encrypted, base64-encoded message
     */
    Optional<String> encrypt(String plainMessage);

    /**
     * Decrypt string-based, base64 encoded message
     * @param encryptedMessage encrypted message, represented as string encoded in base64
     * @return plain text
     */
    Optional<String> decrypt(String encryptedMessage);
}
