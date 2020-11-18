package andreas19.gemina4j;

/**
 * Thrown to indicate that data could not be decrypted.
 */
public class DecryptException extends Exception {
    DecryptException(String message) {
        super(message);
    }
}
