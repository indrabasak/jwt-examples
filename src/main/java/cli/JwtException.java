package cli;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * {@code JwtException}
 *
 * @author Indra Basak
 * @since 1/24/17
 */
@NoArgsConstructor
@ToString(callSuper = true)
@Getter
@Setter
public class JwtException extends Exception {

    public JwtException(String message) {
        super(message);
    }

    public JwtException(Throwable cause) {
        super(cause);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }
}