import java.util.Base64;

public class Util {
  // Encoding only: decode-scan must NOT flag this file.
  public String encode(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }
}
