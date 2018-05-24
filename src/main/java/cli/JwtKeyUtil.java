package cli;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.HmacKey;

/**
 * {@code JwtKeyUtil}
 *
 * @author Indra Basak
 * @since 1/24/17
 */
@Slf4j
public class JwtKeyUtil {

    public static Key generateKey(AlgorithmType algo, String subscriberId,
            String user,
            String password) throws JwtException {
        //SHA256($subscriber_id + "/" + $sub + ":" + SHA256($subscriber_id + $password))
        Key key;

        try {
            String subIdPwd = String.format("%1$s%2$s", subscriberId, password);
            subIdPwd = StringUtils.replace(subIdPwd, "*", "%2A");
            byte[] pwdHash = getShaHash(algo, subIdPwd.getBytes("UTF-8"));
            String subIdUser = String.format("%1$s/%2$s:", subscriberId, user);
            byte[] subIdUserPwdHash =
                    ArrayUtils.addAll(subIdUser.getBytes("UTF-8"), pwdHash);
            byte[] hash = getShaHash(algo, subIdUserPwdHash);
            key = new HmacKey(hash);
        } catch (UnsupportedEncodingException e) {
            throw new JwtException("Failed to create key.", e);
        }

        return key;
    }

    public static Key deriveKey(AlgorithmType algo, String subscriberId,
            String user,
            String encodedpassword) throws JwtException {

        Key key;

        try {
            byte[] pwdHash = Hex.decodeHex(encodedpassword.toCharArray());
            String subIdUser = String.format("%1$s/%2$s:", subscriberId, user);
            byte[] subIdUserPwdHash =
                    ArrayUtils.addAll(subIdUser.getBytes("UTF-8"), pwdHash);
            byte[] hash = getShaHash(algo, subIdUserPwdHash);
            key = new HmacKey(hash);
        } catch (DecoderException e) {
            throw new JwtException("Failed to decode password", e);
        } catch (UnsupportedEncodingException e) {
            throw new JwtException(e);
        }

        return key;
    }

    public static byte[] getShaHash(AlgorithmType algo, byte[] data)
            throws UnsupportedEncodingException {
        byte[] hash;

        switch (algo) {
            case SHA384:
                hash = DigestUtils.sha384(data);
                break;
            case SHA512:
                hash = DigestUtils.sha512(data);
                break;
            default:
                hash = DigestUtils.sha256(data);
                System.out.println("&&&&&&& " + DigestUtils.sha256Hex(data));
        }

        return hash;
    }

    public static AlgorithmType getAlgorithmType(
            String alg) throws JwtException {

        AlgorithmType algoType = null;

        if (alg == null) {
            throw new JwtException("Null hash algorithm");
        }

        switch (alg.toUpperCase()) {
            case AlgorithmIdentifiers.HMAC_SHA256:
            case "S256":
            case "SHA256":
                algoType = AlgorithmType.SHA256;
                break;
            case AlgorithmIdentifiers.HMAC_SHA384:
            case "S384":
            case "SHA384":
                algoType = AlgorithmType.SHA384;
                break;
            case AlgorithmIdentifiers.HMAC_SHA512:
            case "S512":
            case "SHA512":
                algoType = AlgorithmType.SHA384;
                break;
            default:
                throw new JwtException("Unknown hash algorithm " + alg);
        }

        return algoType;
    }

    public static String urlEncode(String value) {
        return urlEncode(value, "UTF-8");
    }

    public static String urlEncode(String value, String encoding) {
        try {
            return value == null ? "" : (StringUtils.isBlank(
                    value) ? value : URLEncoder.encode(value, encoding));
        } catch (UnsupportedEncodingException var3) {
            log.error(var3.getMessage(), var3);
            return null;
        }
    }
}
