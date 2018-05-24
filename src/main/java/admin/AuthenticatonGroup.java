package admin;

import java.util.List;

/**
 * {@code AuthenticatonGroup}
 *
 * @author Indra Basak
 * @since 2/21/17
 */
public class AuthenticatonGroup {

    private String op;

    private List<Authenticator> authenticators;

    private List<AuthenticatonGroup> groups;
}
