package io.finn.signald;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

public class ManagerFactory {
    private static String dataPath;
    private static ConcurrentHashMap<String, Manager> managers;
    private static final Logger logger = LogManager.getLogger();

    public static void setDataPath(String path) {
        dataPath = path;
    }

    public static String getDataPath() {
        return dataPath;
    }

    public static Manager getManager() {
        return new Manager(null, dataPath);
    }

    public static Manager getManager(String username) throws IOException {
        // So many problems in this method, need to have a single place to create new managers, probably in MessageReceiver

        if (managers.containsKey(username)) {
            return managers.get(username);
        } else {
            logger.info("Creating a manager for " + username);
            Manager m = new Manager(username, dataPath);
            if (m.userExists()) {
                m.init();
            } else {
                logger.warn("Created manager for a user that doesn't exist! (" + username + ")");
            }
            managers.put(username, m);
            return m;
        }
    }

    public static void putManager(Manager m){
        if(!m.userExists()){
            return;
        }
        managers.put(m.getUsername(), m);
    }

    public static ConcurrentHashMap<String, Manager> getManagers() {
        return new ConcurrentHashMap<>(managers);
    }
}
