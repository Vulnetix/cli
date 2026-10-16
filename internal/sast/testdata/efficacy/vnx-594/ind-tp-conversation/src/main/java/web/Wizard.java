package web;

import javax.enterprise.context.ConversationScoped;
import javax.inject.Named;

@Named
@ConversationScoped
~>public class Wizard {
    private int step;
}
