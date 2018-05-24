package jose4j;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * {@code Request}
 *
 * @author Indra Basak
 * @since 1/16/17
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Request {
    private String meth;

    private String path;

    private String query;

    private String func;

    private String hash;

    private String body;
}
