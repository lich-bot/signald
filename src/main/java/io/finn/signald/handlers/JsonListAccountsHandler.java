package io.finn.signald.handlers;

import io.finn.signald.JsonAccountList;
import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.ManagerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class JsonListAccountsHandler extends BaseJsonHandler {

    private ArrayList<String> subscribedAccounts;

    public JsonListAccountsHandler(ArrayList<String> subscribedAccounts ) {
        this.subscribedAccounts = subscribedAccounts;
    }

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    // We have to create a manager for each account that we're listing, which is all of them :/
    File[] users = new File(ManagerFactory.getDataPath() + "/data").listFiles();
    if (users != null) {
        for (File user : users) {
            if (!user.isDirectory()) {
                ManagerFactory.getManager(user.getName());
            }
        }
    }

    JsonAccountList accounts = new JsonAccountList(ManagerFactory.getManagers(), this.subscribedAccounts);
    return new JsonMessageWrapper("account_list", accounts, request.id);
  }
}
