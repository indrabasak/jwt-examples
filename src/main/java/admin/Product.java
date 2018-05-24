package admin;

import java.util.UUID;
import lombok.Getter;
import lombok.Setter;

/**
 * {@code Product}
 *
 * @author Indra Basak
 * @since 2/21/17
 */
@Getter
@Setter
public class Product {

    private UUID productId;

    private String name;

    private String provider;

    private String category;

    private int challengeTTL;

    private int tmpAbsoluteTTL;

    private int tmpInactiveTTL;

    private int regAbsoluteTTL;

    private int regInactiveTTL;
}
