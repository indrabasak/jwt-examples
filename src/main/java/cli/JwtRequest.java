package cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * {@code JwtRequest}
 *
 * @author Indra Basak
 * @since 1/24/17
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JwtRequest {
    private String meth;

    private String path;

    private String query;

    private String func;

    private String hash;

    private String body;
}
