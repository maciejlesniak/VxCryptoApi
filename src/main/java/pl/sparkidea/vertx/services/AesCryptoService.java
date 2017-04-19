package pl.sparkidea.vertx.services;

import com.hazelcast.util.StringUtil;

import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

/**
 * AES encrypt / decrypt based on 128 bit key and 16 byte init vector
 *
 * @author Maciej Lesniak / Spark Media
 * @version 19/04/2017
 */
public class AesCryptoService implements CryptoService {
    private Logger LOG = LoggerFactory.getLogger(AesCryptoService.class);

    private final static String CIPHER_INSTANCE_NAME = "AES/CBC/PKCS5PADDING";
    private final static String CIPHER_ALGORITHM_NAME = "AES";

    public final static String CONFIG_KEY_FIELD_NAME = "key";
    public final static String CONFIG_INIT_VECTOR_FIELD_NAME = "initVector";

    private final static String EX_MESSAGE_PREFIX = "crypto service configuration error: ";
    private final static String EX_MESSAGE_EMPTY = "empty key or init vector";
    private final static String EX_MESSAGE_NOT_128BIT = "key and init vector must be 128-bit long";

    private final byte MIN_KEY_LENGTH = 16;
    private final byte MIN_INIT_VECTOR_LENGTH = 16;

    private byte[] key;
    private byte[] initVector;

    /**
     * Constructs AES crypto service using config with 2 fields: key and initVector
     *
     * @param config JsonObject with configuration
     * @throws RuntimeException when there is empty key or init vector, or key or init vector length is less then 16 bytes
     */
    public AesCryptoService(JsonObject config) {
        String initVectorBase64 = config.getString(CONFIG_INIT_VECTOR_FIELD_NAME);
        String keyBase64 = config.getString(CONFIG_KEY_FIELD_NAME);

        if (StringUtil.isNullOrEmpty(initVectorBase64) || StringUtil.isNullOrEmpty(keyBase64)) {
            throw new RuntimeException(EX_MESSAGE_PREFIX + EX_MESSAGE_EMPTY);
        }

        this.initVector = Base64.getDecoder().decode(initVectorBase64);
        this.key = Base64.getDecoder().decode(keyBase64);

        if (this.initVector.length < MIN_INIT_VECTOR_LENGTH || this.key.length < MIN_KEY_LENGTH) {
            throw new RuntimeException(EX_MESSAGE_PREFIX + EX_MESSAGE_NOT_128BIT);
        }
    }

    /**
     * Encrypt given bytes
     *
     * @param plainMessage unencrypted message as bytes
     * @return encrypted message as bytes
     */
    @Override
    public byte[] encrypt(byte[] plainMessage) {
        byte[] encryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, CIPHER_ALGORITHM_NAME);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            encryptedMessage = cipher.doFinal(plainMessage);
        } catch (Exception ex) {
            LOG.error(ex.getMessage());
        }
        return encryptedMessage;
    }

    /**
     * Decrypt given bytes
     *
     * @param encryptedMessage encrypted message as bytes
     * @return bytes with decrypted message
     */
    @Override
    public byte[] decrypt(byte[] encryptedMessage) {
        byte[] plainMessage = null;
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, CIPHER_ALGORITHM_NAME);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            plainMessage = cipher.doFinal(encryptedMessage);
        } catch (Exception ex) {
            LOG.error(ex.getMessage());
        }

        return plainMessage;
    }

    /**
     * Base64-encoded string encryption
     *
     * @param plainMessage plain message, base64 encoded
     * @return encrypted message, base64 encoded (if any)
     */
    @Override
    public Optional<String> encrypt(String plainMessage) {
        Optional<String> encrypted = Optional.empty();
        if (!StringUtil.isNullOrEmpty(plainMessage)) {
            byte[] plainMessageBytes = plainMessage.getBytes();
            byte[] encryptedBytes = encrypt(plainMessageBytes);
            encrypted = Optional.of(Base64.getEncoder().encodeToString(encryptedBytes));
        }
        return encrypted;
    }

    /**
     * Base64-encoded string decryption
     *
     * @param encryptedMessage encrypted message, represented as string encoded in base64
     * @return plain text (if any)
     */
    @Override
    public Optional<String> decrypt(String encryptedMessage) {
        Optional<String> decrypted = Optional.empty();
        if (!StringUtil.isNullOrEmpty(encryptedMessage)) {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] plainMessageBytes = decrypt(encryptedBytes);
            decrypted = Optional.of(new String(plainMessageBytes));
        }
        return decrypted;
    }
}
