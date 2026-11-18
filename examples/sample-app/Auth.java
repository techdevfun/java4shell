import java.util.Base64;

public class Auth {
  // REVIEW: decodes a Base64 value taken from an HTTP header.
  // Whether untrusted input reaches this call decides exposure;
  // the tool reports the site, it never claims exploitability.
  public byte[] credentials(String header) {
    return Base64.getDecoder().decode(header);
  }
}
