import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class CodeDecodeAES {
    static Cipher cipher;

    public static void main(String[] args) throws Exception {
        // Generate a 128-bit AES key (use 256 for AES-256 if supported)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // Initialize the cipher for AES-GCM mode
        cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Plaintext to be encrypted
        String plainText = "AES GCM Encryption Decryption Example";
        System.out.println("Plain Text Before Encryption: " + plainText);

        // Encrypt the plaintext
        String encryptedText = encrypt(plainText, secretKey);
        System.out.println("Encrypted Text After Encryption: " + encryptedText);

        // Decrypt the ciphertext
        String decryptedText = decrypt(encryptedText, secretKey);
        System.out.println("Decrypted Text After Decryption: " + decryptedText);
    }

    private static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        // Decode the Base64-encoded ciphertext into a byte array
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);

        // Extract the IV (first 12 bytes) and the ciphertext (remaining bytes)
        byte[] iv = new byte[12]; // IV is 12 bytes
        byte[] cipherText = new byte[encryptedTextByte.length - 12]; // Ciphertext + Authentication Tag
        System.arraycopy(encryptedTextByte, 0, iv, 0, 12);
        System.arraycopy(encryptedTextByte, 12, cipherText, 0, cipherText.length);

        // Initialize the cipher in decryption mode with the secret key and IV
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        // Decrypt the ciphertext
        byte[] decryptedByte = cipher.doFinal(cipherText);

        // Convert the decrypted bytes to a string
        return new String(decryptedByte);
    }

    private static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        // Convert the plaintext into a byte array
        byte[] plainTextByte = plainText.getBytes();

        // Generate a random IV (12 bytes)
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);

        // Initialize the cipher in encryption mode with the secret key and IV
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        // Encrypt the plaintext byte array
        byte[] encryptedByte = cipher.doFinal(plainTextByte);

        // Concatenate the IV and the ciphertext (IV + Ciphertext)
        byte[] result = new byte[12 + encryptedByte.length];
        System.arraycopy(iv, 0, result, 0, 12);
        System.arraycopy(encryptedByte, 0, result, 12, encryptedByte.length);

        // Encode the result as a Base64 string
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(result);
    }
}
