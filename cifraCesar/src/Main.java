public class Main {



    public static void main(String[] args) {
        String input = "Testando a função";
        char [] charInput= input.toCharArray();
        String cryptografada = "";

        for (char c : charInput) {
            cryptografada += (char) (c + 4);
        }

        String descriptografada = "";

        char [] charCryptografada = cryptografada.toCharArray();

        for (char c : charCryptografada) {
            descriptografada += (char) (c - 4);
        }

        System.out.println("Input: " + input);
        System.out.println("Cryptografada: " + cryptografada);
        System.out.println("Descriptografada: " + descriptografada);


    }
}