package cracker;

class PasswordCrackerConsts {

    static final String PASSWORD_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[{#";

    private final int passwordLength;
    private final long passwordSubRangeSize;
    private final String encryptedPassword;
    
    PasswordCrackerConsts(int numThreads, int passwordLength, String encryptedPassword) {
        this.passwordLength = passwordLength;
        this.encryptedPassword = encryptedPassword;
        long passwordRangeSize = (long) Math.pow(PASSWORD_CHARS.length(), passwordLength);
        passwordSubRangeSize = (passwordRangeSize + numThreads - 1) / numThreads;
    }
    
    int getPasswordLength() {
        return passwordLength;
    }

    long getPasswordSubRangeSize() {
        return passwordSubRangeSize;
    }
    
    String getEncryptedPassword() {
        return encryptedPassword;
    }
}
