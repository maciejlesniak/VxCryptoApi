package pl.sparkidea.vertx;

import pl.sparkidea.vertx.services.AesCryptoService;
import pl.sparkidea.vertx.services.CryptoService;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

/**
 * Proof of concept: crypto service
 *
 * @author Maciej Lesniak / Spark Media
 * @version 19/04/2017
 * @see CryptoService
 * @see AesCryptoService
 */
public class VxCrypto extends AbstractVerticle {

    private Logger LOG = LoggerFactory.getLogger(VxCrypto.class);
    private final String CONFIG_CRYPTO_FIELD = "cryptoConfig";

    @Override
    public void start() throws Exception {
        super.start();

        LOG.debug("VxConfiguration: " + config().toString());

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);

        String randomKey = Base64.getEncoder().encodeToString(bytes);
        LOG.debug("Random generated key / vector encoded in Base64: " + randomKey);

        CryptoService cryptoService = new AesCryptoService(config().getJsonObject(CONFIG_CRYPTO_FIELD));
        vertx.executeBlocking(executeBlockingCode(cryptoService), voidAsyncResult -> {
            if (voidAsyncResult.succeeded()) {
                LOG.info("SUCCESS");
            } else {
                LOG.info("FAILURE");
            }
        });

    }

    private Handler<Future<Void>> executeBlockingCode(CryptoService cryptoService) {
        return voidFuture -> {
            cryptoService.encrypt("Dummy message").ifPresent(encryptedMessage -> {
                LOG.debug("encrypted message (base64 encoded): " + encryptedMessage);
                Optional<String> decryptedMessage = cryptoService.decrypt(encryptedMessage);
                if (decryptedMessage.isPresent()) {
                    LOG.debug("decrypted message: " + decryptedMessage.get());
                    voidFuture.complete();
                } else {
                    LOG.error("no decrypted message");
                    voidFuture.fail("no decrypted message");
                }
            });
        };
    }
}
