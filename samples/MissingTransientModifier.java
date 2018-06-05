public class MissingTransientModifier {

    public static void main(String[] args) throws Exception {
        Thread thread = new Thread(MissingTransientModifier::run);
        thread.start();
        Thread.sleep(100);

        finished = true;

        System.out.println("finished = true");
        thread.join(5000l);
    }

    private static boolean finished = false;

    public static void run() {
        System.out.println("run() entry");
        while (!finished) { }
        System.out.println("run() exit");
    }
}