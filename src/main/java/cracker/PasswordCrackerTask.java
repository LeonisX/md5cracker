package cracker;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static cracker.PasswordCrackerConsts.PASSWORD_CHARS;

public class PasswordCrackerTask implements Runnable {

    private final boolean lead;
    private int taskId;
    private PasswordFuture passwordFuture;
    private PasswordCrackerConsts consts;
    private long percent = -1;
    private long fromTime = System.nanoTime();

    PasswordCrackerTask(int taskId, PasswordCrackerConsts consts, PasswordFuture passwordFuture, boolean lead) {
        this.taskId = taskId;
        this.consts = consts;
        this.passwordFuture = passwordFuture;
        this.lead = lead;
    }

    /* ### run ###

     */
    @Override
    public void run() {
        long rangeBegin = ((long) taskId) * consts.getPasswordSubRangeSize();
        long rangeEnd = rangeBegin + consts.getPasswordSubRangeSize();

        String passwordOrNull = findPasswordInRange(rangeBegin, rangeEnd, consts.getEncryptedPassword());

        passwordFuture.set(passwordOrNull);
    }

    /*	### findPasswordInRange	###
     * The findPasswordInRange method find the original password using md5 hash function
     * if a thread discovers the password, it returns original password string; otherwise, it returns null;
     */
    private String findPasswordInRange(long rangeBegin, long rangeEnd, String encryptedPassword) {
        long diff = rangeEnd - rangeBegin;
        char passwdFirstChar = encryptedPassword.charAt(0);    // Our little optimization
        int[] arrayKey = new int[consts.getPasswordLength()];  // The array which holds each alpha-num item
        String passwd = null;

        // Compute first array
        long longKey = rangeBegin;
        transformDecToBaseXX(longKey, arrayKey);

        for (; longKey < rangeEnd && !(passwordFuture.isDone()); longKey++) {
            if (lead && consts.getPasswordLength() >= 6) {
                long newPercent = (longKey - rangeBegin) * 100 / diff;
                if (percent != newPercent) {
                    percent = newPercent;
                    long timeElapsed = (System.nanoTime() - fromTime) / 1000000000;
                    System.out.println(percent + " (" + timeElapsed + "s)");
                    fromTime = System.nanoTime();
                }
            }
            String rawKey = transformIntToStr(arrayKey);
            String md5Key = encrypt(rawKey, getMessageDigest());

            // Avoid full string comparison
            if (md5Key.charAt(0) == passwdFirstChar) {
                if (encryptedPassword.equals(md5Key)) {
                    passwd = rawKey;
                    break;
                }
            }
            getNextCandidate(arrayKey);
        }

        return passwd;
    }

    /*
     * The transformDecToBaseXX transforms decimal into numArray that is base XX number system
     * Where XX == PASSWORD_CHARS.length
     */
    private static void transformDecToBaseXX(long numInDec, int[] numArrayInBaseXX) {
        long quotient = numInDec;
        int passwdlength = numArrayInBaseXX.length - 1;

        for (int i = passwdlength; quotient > 0L; i--) {
            int reminder = (int) (quotient % PASSWORD_CHARS.length());
            quotient /= PASSWORD_CHARS.length();
            numArrayInBaseXX[i] = reminder;
        }
    }

    /*
     * The getNextCandidate update the possible password represented by XX base system
     */
    private static void getNextCandidate(int[] candidateChars) {
        int i = candidateChars.length - 1;

        while (i >= 0) {
            candidateChars[i] += 1;

            if (candidateChars[i] >= PASSWORD_CHARS.length()) {
                candidateChars[i] = 0;
                i--;

            } else {
                break;
            }
        }
    }

    /*
     * We assume that each character can be represented to a number : 0 (0) , 1 (1), 2 (2) ... a (10), b (11), c (12), ... x (33), y (34), z (35)
     * The transformIntToStr transforms int-array into string (numbers and lower-case alphabets)
     * int array is password represented by base-XX system
     * return : password String
     *
     * For example, if you write the code like this,
     *     int[] pwdBaseXX = {10, 11, 12, 13, 0, 1, 9, 2};
     *     String password = transfromIntoStr(pwdBaseXX);
     *     System.out.println(password);
     *     output is abcd0192.
     *
     */
    private static String transformIntToStr(int[] chars) {
        char[] password = new char[chars.length];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_CHARS.charAt(chars[i]);
        }
        return new String(password);
    }

    private static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot use MD5 Library:" + e.getMessage());
        }
    }

    private static String encrypt(String password, MessageDigest messageDigest) {
        messageDigest.update(password.getBytes());
        byte[] hashedValue = messageDigest.digest();
        return byteToHexString(hashedValue);
    }

    private static String byteToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte aByte : bytes) {
            String hex = Integer.toHexString(0xFF & aByte);
            if (hex.length() == 1) {
                builder.append('0');
            }
            builder.append(hex);
        }
        return builder.toString();
    }
}
