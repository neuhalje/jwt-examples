package name.neuhalfen.examples.jwt;

import at.favre.lib.crypto.HKDF;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

/**
 * This class is a more or less random collection. Use at your own risk!!!
 */
public class JwtExample {
    public static byte[] generateSharedSecret() {
        // Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);
        return sharedSecret;
    }

    private static byte[] hkdf(final byte[] sharedSecret, final String info, int lengthInBytes) {
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(sharedSecret, info.getBytes(StandardCharsets.UTF_8), lengthInBytes);
    }

    private SignedJWT parseJWT(final byte[] sharedKey,
                               final String keyId,
                               final String jwt) throws JOSEException, ParseException {
        final byte[] jwtKey = deriveJwtKey(sharedKey);

        final SignedJWT signedJWT = SignedJWT.parse(jwt);
        // in a real world this would be: parse; get key Id; get key(keyID)
        assert keyId.equals(signedJWT.getHeader().getKeyID());
        // Protect agains token with "none" integrity
        assert JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm());

        final JWSVerifier verifier = new MACVerifier(jwtKey);

        // tampered!
        if (!signedJWT.verify(verifier)) throw new RuntimeException("TAMPERED TOKEN");

        // Too old
        if (!(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())))
            throw new RuntimeException("Token too old");

        // ... wrong audience, wrong subject, ... --
        return signedJWT;
    }

    private byte[] deriveJwtKey(final byte[] sharedSecret) {
        return hkdf(sharedSecret, "K.2", 32);
    }

    private byte[] deriveJweKey(final byte[] sharedSecret) {
        return hkdf(sharedSecret, "K.1", 16);
    }

    /**
     * This is an integrity protected JWT token. It is NOT encrypted.
     */
    public String createJWTFromSharedSecret(final byte[] sharedSecret,
                                            String kid,
                                            final String subject,
                                            final String issuer,
                                            final String audience,
                                            final Date expirationTime) throws JOSEException {
        byte[] jwtKey = deriveJwtKey(sharedSecret);
        return createJWT(jwtKey, kid, subject, issuer, audience, expirationTime);
    }

    /**
     * This is an integrity protected JWT token inside an encrypted, integrity protected JWE
     */
    public String createEncryptedJWTFromSharedSecret(final byte[] sharedSecret,
                                                     final String kid,
                                                     final String subject,
                                                     final String issuer,
                                                     final String audience,
                                                     final Date expirationTime) throws JOSEException, NoSuchAlgorithmException {
        byte[] jwtKey = deriveJwtKey(sharedSecret);
        final String jwt = createJWT(jwtKey, kid, subject, issuer, audience, expirationTime);

        //
        byte[] jweKey = deriveJweKey(sharedSecret);

        return createJWE(jweKey, kid, jwt);
    }

    /**
     * This is an *unprotected* JWT token inside an encrypted, integrity protected JWE
     */
    public String createEncryptedJWTFromSharedSecretUnsignedJWT(final byte[] sharedSecret,
                                                     final String kid,
                                                     final String subject,
                                                     final String issuer,
                                                     final String audience,
                                                     final Date expirationTime) throws JOSEException, NoSuchAlgorithmException {
        final String jwt = createUnsignedJWT(subject, issuer, audience, expirationTime);

        // Always use HKDF on key material
        byte[] jweKey = deriveJweKey(sharedSecret);

        return createJWE(jweKey, kid, jwt);
    }

    private String createJWE(final byte[] jweKey,
                             String kid,
                             final String jwt) throws NoSuchAlgorithmException, JOSEException {
        assert jweKey.length == 16;

        final SecretKeySpec secretKey = new SecretKeySpec(jweKey, "AES");

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM).keyID(kid).build();
        Payload payload = new Payload(jwt);

        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(secretKey));
        return jweObject.serialize();
    }

    public String parseJwe(final byte[] sharedSecret, final String kid, final String jwe) throws ParseException, JOSEException {
        final JWEObject jweObject = JWEObject.parse(jwe);

        final byte[] jweKey = deriveJweKey(sharedSecret);
        // Real world: parse;getKeyId; getKey(keyId)
        assert kid.equals(jweObject.getHeader().getKeyID());
        assert JWEAlgorithm.A128GCMKW.equals(jweObject.getHeader().getAlgorithm());

        jweObject.decrypt(new DirectDecrypter(jweKey));

        return jweObject.getPayload().toString();
    }

    private String createJWT(final byte[] jwtKey,
                             String kid,
                             final String subject,
                             final String issuer,
                             final String audience,
                             final Date expirationTime) throws JOSEException {
        final JWSSigner signer = new MACSigner(jwtKey);

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .expirationTime(expirationTime)
                .audience(audience)
                .build();

        final SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(kid).build(),
                claimsSet);
        signedJWT.sign(signer);

        // eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJpc3MiOiJBQ01FIENvcnBcL2RlbW8tY2FzZVwvVEVTVCIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiQUNNRSBDb3JwXC9kZW1vLWF1ZGllbmNlXC9URVNUIiwiZXhwIjoxNjQ4MjExODM1fQ.Cayz17JfZSixNKqwY0JjEIeyW2711GzhMc6mBru3do0
        return signedJWT.serialize();
    }

    private String createUnsignedJWT(final String subject,
                             final String issuer,
                             final String audience,
                             final Date expirationTime)  {

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .expirationTime(expirationTime)
                .audience(audience)
                .build();


         return new PlainJWT( claimsSet).serialize();
    }


    public static void main(String[] args) throws JOSEException, NoSuchAlgorithmException, ParseException {
        final Date expirationDate = new Date(new Date().getTime() + 60 * 1000);

        // in a real world application the shared secret would be semi-static and bound to the key id.
        // semi-static means: Changed every few GiB of data/every few years.
        final byte[] sharedSecret = generateSharedSecret();
        final JwtExample sut = new JwtExample();

        System.out.println("Shared secret              : " + Arrays.toString(sharedSecret));
        //
        System.out.println("Example derived 4-byte key for K.1: " + Arrays.toString(hkdf(sharedSecret, "K.1", 4)));
        System.out.println("Example derived 4-byte key for K.2: " + Arrays.toString(hkdf(sharedSecret, "K.2", 4)));

        // jwt: not encrypted
        final String jwt = sut.createJWTFromSharedSecret(sharedSecret, "1", "John Doe", "ACME Corp/demo-case/TEST", "ACME Corp/demo-audience/TEST", expirationDate);
        System.out.println("Signed JWT      | Signed JWT (len: " + jwt.length() + ")   : " + jwt);

        // jwe: encrypted
        final String jwe = sut.createEncryptedJWTFromSharedSecret(sharedSecret, "1", "John Doe", "ACME Corp/demo-case/TEST", "ACME Corp/demo-audience/TEST", expirationDate);
        System.out.println("Signed JWT      | Signed & Enc JWT (len: " + jwe.length() + "; "+ (jwe.length()-jwt.length()) +" bytes overhead): " + jwe);

        // and back again
        final String jwtFromJwe = sut.parseJwe(sharedSecret,"1", jwe);

        SignedJWT parsedJwt = sut.parseJWT(sharedSecret, "1", jwtFromJwe);
        System.out.println("Signed JWT      | Parsed JWT: " + parsedJwt.getParsedString());

        System.out.println("Signed JWT      | Parsed JWT: Hello, " + parsedJwt.getJWTClaimsSet().getSubject());

        assert parsedJwt.getJWTClaimsSet().getSubject().equals("John Doe");

        // This is NOT recommended
        final String unsignedJwt = sut.createUnsignedJWT( "John Doe", "ACME Corp/demo-case/TEST", "ACME Corp/demo-audience/TEST", expirationDate);
        System.out.println("Unsigned JWT    | Unsigned JWT (len: " + unsignedJwt.length() + "  : " + unsignedJwt);

        final String jweFromUnsignedJWT = sut.createEncryptedJWTFromSharedSecretUnsignedJWT(sharedSecret, "1", "John Doe", "ACME Corp/demo-case/TEST", "ACME Corp/demo-audience/TEST", expirationDate);
        System.out.println("Unsigned JWT    | Signed & Enc JWT (len: " + jweFromUnsignedJWT.length() + "; "+ (jweFromUnsignedJWT.length()-unsignedJwt.length()) +" bytes overhead): " + jweFromUnsignedJWT);

    }

}
