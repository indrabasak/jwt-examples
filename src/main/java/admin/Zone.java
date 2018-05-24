package admin;

import java.util.UUID;
import lombok.Getter;
import lombok.Setter;

/**
 * {@code Zone}
 *
 * @author Indra Basak
 * @since 2/21/17
 */
@Getter
@Setter
public class Zone {
    private UUID zoneId;

    private String name;

    private String notes;

    private String riskPolicy;

    private String matchSensitivity;
}
