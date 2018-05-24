package cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * {@code Response}
 *
 * @author Indra Basak
 * @since 1/29/17
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Response {

    private int status;

    //same value as the 'Cache-Control' header, if any
    private String cache;

    //Same value as the Location header, if any
    private String location;

    private String body;
}
