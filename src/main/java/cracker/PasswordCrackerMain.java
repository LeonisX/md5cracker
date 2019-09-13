package cracker;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class PasswordCrackerMain {
    public static void main(String[] args) {

        if (args.length < 3) {
            System.out.println("Usage: PasswordCrackerMain numThreads minPasswordLength maxPasswordLength encryptedPassword");
            return;
        }

        int minPasswordLength = Integer.parseInt(args[1]);
        int maxPasswordLength = Integer.parseInt(args[2]);
        String encryptedPassword = args[3].toLowerCase();

        /*
         * Create PasswordCrackerTask and use executor service to run in a separate thread
         */

        long fromTime = System.nanoTime();

        String passwd = null;
        for (int len = minPasswordLength; len <= maxPasswordLength; len++) {

            int numThreads = (len == 1) ? 1 : Integer.parseInt(args[0]);
            ExecutorService workerPool = Executors.newFixedThreadPool(numThreads);
            PasswordFuture passwordFuture = new PasswordFuture(numThreads);
            System.out.println("Passwords for length: " + len);
            PasswordCrackerConsts consts = new PasswordCrackerConsts(numThreads, len, encryptedPassword);

            boolean lead = true;

            for (int i = 0; i < numThreads; i++) {
                workerPool.submit(new PasswordCrackerTask(i, consts, passwordFuture, lead));
                lead = false;
            }

            try {
                passwd = passwordFuture.get();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                workerPool.shutdown();
            }
            if (passwd != null) {
                break;
            }
        }

        System.out.println("==================");

        long timeElapsed = (System.nanoTime() - fromTime) / 1000000000;
        System.out.println(timeElapsed);
        System.out.println(encryptedPassword);
        System.out.println(passwd);
    }
}

class PasswordFuture implements Future<String> {

    private String result;
    private Lock lock = new ReentrantLock();
    private Condition resultSet = lock.newCondition(); // refer to Condition and Lock class in javadoc
    private int numThreads;
    private int count = 0;

    PasswordFuture(int numThreads) {
        this.numThreads = numThreads;
    }

    /*  ### set ###
     *  set the result and send signal to thread waiting for the result
     */
    void set(String result) {
        lock.lock();
        if (result != null) {
            this.result = result;
        }
        count++;
        resultSet.signal();
        lock.unlock();
    }

    /*  ### get ###
     *  if result is ready, return it.
     *  if not, wait on the conditional variable.
     */
    public String get() throws InterruptedException {
        lock.lock();
        try {
            while (!isDone()) {
                // No routine to catch the InterruptedException, out of the scope of 
                // this assignment
                resultSet.await();
            }
        } finally {
            lock.unlock();
        }

        return result;
    }
    /*  ### isDone ###
     *  returns true if result is set
     */
    public boolean isDone() {
        // Java references read/write are atomic operations
        // No need to explicitily ensure mutual exclusion.
        return (numThreads == count) || result != null;
    }

    public boolean cancel(boolean mayInterruptIfRunning) {
        return false;
    }

    public boolean isCancelled() {
        return false;
    }

    public String get(long timeout, TimeUnit unit) {
        // no need to implement this. We don't use this...
        return null;
    }
}
