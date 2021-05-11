package com.github.qhh6eq.http;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public final class EasyHttpAuthentication {

    private static String base64(String str) {
        return Base64.getEncoder().encodeToString(str.getBytes());
    }

    private static String md5(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(str.getBytes());
        return DatatypeConverter.printHexBinary(messageDigest.digest()).toLowerCase();
    }

    private static final Object LOCK = new Object();
    private static final Map<String, Integer> NC_MAP = new WeakHashMap<>();
    private static Integer nc(String nonce) {
        synchronized (LOCK) {
            return NC_MAP.compute(nonce, (key, oldValue) -> oldValue == null || oldValue > 10_000_000 ? 1 : oldValue + 1);
        }
    }

    private static String cnonce() {
        return UUID.randomUUID().toString();
    }

    /**
     *
     * @param authenticationType authenticationType
     * @param authenticate http herder WWW-Authenticate value
     * @return
     */
    public static Map<String, String> authenticateMap(AuthenticationType authenticationType, String authenticate) {
        int beginIndex;
        switch (authenticationType) {
            case BASIC:
                beginIndex = 6;
                break;
            case DIGEST:
                beginIndex = 7;
                break;
            default: return Collections.emptyMap();
        }
        final Map<String, String> authenticateMap = Arrays.stream(authenticate.substring(beginIndex).split(", "))
                .map(kv -> kv.split("="))
                .collect(Collectors.toMap(x -> x[0], x -> x[1].replaceAll("\"", "")));
        return authenticateMap;
    }

    public enum AuthenticationType {
        BASIC, DIGEST, OTHER;

        /**
         * http herder WWW-Authenticate value
         */
        public static AuthenticationType find(String authenticate) {
            if (authenticate == null || authenticate.length() < 6) return OTHER;
            else if ("Basic".equals(authenticate.substring(0, 5))) return BASIC;
            else if ("Digest".equals(authenticate.substring(0, 6))) return DIGEST;
            else return OTHER;
        }
    }

    public static String basic(
            // ==========server
            String realm,
            // ==========client
            String username,
            String password
    ) {
        return "Basic " + base64(username + ":" + password);
    }

    public static String digest(
            // ==========server
            String algorithm,
            String realm,
            String nonce,
            String qop,
            String opaque,
            // ==========client
            String username,
            String password,
            String method,
            String uri,
            Integer nc,
            String cnonce
    ) throws NoSuchAlgorithmException {
        nc = nc == null || nc <= 0 ? nc(cnonce) : nc;
        cnonce = cnonce == null ? cnonce() : cnonce;

        final String a1 = username + ":" + realm + ":" + password;
        final String a2 = method + ":" + uri;

        String response;
        final boolean authExist = "auth".equals(qop);
        final boolean opaqueExist = opaque != null;

        if (!authExist) {
            String tempA = md5(a1) + ":" + nonce + ":" + md5(a2);
            response = md5(tempA);
        } else {
            String tempA = md5(a1) + ":" + nonce
                    + ":" + nc + ":" + cnonce + ":" + qop
                    + ":" + md5(a2);
            response = md5(tempA);
        }

        String authorization = "Digest username=\"" + username + "\"" +
                ", realm=\"" + realm + "\"" +
                ", nonce=\"" + nonce + "\"" +
                ", uri=\"" + uri + "\"" +
                ", algorithm=MD5" +  //
                ", response=\"" + response + "\"" +
                (opaqueExist ? ", opaque=\"" + opaque + "\"" : "") +
                (authExist ? (", qop=" + qop +
                        ", nc=" + nc +
                        ", cnonce=\"" + cnonce + "\"") : "");

        return authorization;
    }

}
