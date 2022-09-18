package org.joget.plugin.marketplace;

import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joget.apps.app.service.AppUtil;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.util.WorkflowUtil;
import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import javax.servlet.http.HttpSession;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.json.JSONObject;

public class JsonWebTokenDirectoryManager extends SecureDirectoryManager {

    public SecureDirectoryManagerImpl dirManager;

    @Override
    public String getName() {
        return "JSON Web Token Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for JSON Web Token";
    }

    @Override
    public String getVersion() {
        return "7.0.0";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        if (dirManager == null) {
            dirManager = new ExtSecureDirectoryManagerImpl(properties);
        } else {
            dirManager.setProperties(properties);
        }

        return dirManager;
    }

    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.marketplace.JsonWebTokenDirectoryManager/service";

        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/JsonWebTokenDirectoryManager.json", new String[]{callbackUrl, usJson, addOnJson}, true, "messages/open-id-authentication");
        return json;
    }

    @Override
    public String getLabel() {
        return "JSON Web Token Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    public static String getCallbackURL() {
        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.marketplace.JsonWebTokenDirectoryManager/service";
        return callbackUrl;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            System.out.println("Key: " + key);
            System.out.println("Value: " + request.getHeader(key));
        }
        String header = request.getHeader("authorization");
        if (header != null) {
            String jwtToken = header.replace("Bearer ", "");

            Map<String, String> UserInfo = decodeJWT(jwtToken);
            doLogin(UserInfo, request, response);
        } else {
            LogUtil.error(getClass().getName(), null, "Missing JSON Web Token in Header");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception("Missing JSON Web Token in Header"));
            String url = request.getContextPath() + "/web/login?login_error=1";
            response.sendRedirect(url);
        }
    }

    private Map<String, String> decodeJWT(String jwtToken) {
        Map<String, String> UserInfo = new HashMap<String, String>();
        JSONObject jsonObject;
        System.out.println("JWT: " + jwtToken);
        String[] chunks = jwtToken.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String header = new String(decoder.decode(chunks[0]));
        System.out.println("Header: " + header);
        String payload = new String(decoder.decode(chunks[1]));
        System.out.println("Payload: " + payload);

        try {
            jsonObject = new JSONObject(payload.trim());
            Iterator<String> keys = jsonObject.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                UserInfo.put(key, jsonObject.getString(key));
            }
        } catch (Exception ex) {
            LogUtil.error(JsonWebTokenDirectoryManager.class.getName(), ex, "");
        }
        return UserInfo;
    }

    void doLogin(Map<String, String> userInfo, HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // read from properties
            DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
            WorkflowUserManager workflowUserManager = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
            SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

            //String certificate = dmImpl.getPropertyString("certificate");
            boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));
            String username;
            if (userInfo.get("preferred_username") != null) {
                username = userInfo.get("preferred_username");
            } else {
                username = userInfo.get("email");
            }

            // get user
            User user = dmImpl.getUserByUsername(username);
            if (user == null && userProvisioningEnabled) {
                // user does not exist, provision
                user = new User();
                user.setId(username);
                user.setUsername(username);
                user.setTimeZone("0");
                user.setActive(1);
                if (userInfo.get("email") != null && !userInfo.get("email").isEmpty()) {
                    user.setEmail(userInfo.get("email"));
                }

                if (userInfo.get("firstName") != null && !userInfo.get("firstName").isEmpty()) {
                    user.setFirstName(userInfo.get("firstName"));
                }

                if (userInfo.get("lastName") != null && !userInfo.get("lastName").isEmpty()) {
                    user.setLastName(userInfo.get("lastName"));
                }
                
                if(user.getFirstName() == null && user.getLastName() == null && userInfo.get("name") != null){
                    String[] fullname = userInfo.get("name").split(" ");
                    user.setFirstName(fullname[0]);
                    user.setLastName(fullname[1]);
                }

                if (userInfo.get("locale") != null && !userInfo.get("locale").isEmpty()) {
                    user.setLocale(userInfo.get("locale"));
                }

                // set role
                RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
                Set roleSet = new HashSet();
                Role r = roleDao.getRole("ROLE_USER");
                if (r != null) {
                    roleSet.add(r);
                }
                user.setRoles(roleSet);
                // add user
                UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                userDao.addUser(user);
            } else if (user == null && !userProvisioningEnabled) {
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                return;
            }

            // verify license
            PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
            DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
            DirectoryManager wrapper = new DirectoryManagerWrapper(dmImpl, true);
            if (user != null) {
                authenticator.authenticate(wrapper, user.getUsername(), user.getPassword());
            }
            // get authorities
            Collection<Role> roles = dm.getUserRoles(username);
            List<GrantedAuthority> gaList = new ArrayList<>();
            if (roles != null && !roles.isEmpty()) {
                for (Role role : roles) {
                    GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                    gaList.add(ga);
                }
            }

            // login user
            UserDetails details = new WorkflowUserDetails(user);
            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
            result.setDetails(details);
            SecurityContextHolder.getContext().setAuthentication(result);
            workflowUserManager.setCurrentThreadUser(user.getUsername());
            
            // add audit trail
            WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
            workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

            // generate new session to avoid session fixation vulnerability
            HttpServletRequest httpRequest = WorkflowUtil.getHttpServletRequest();
            HttpSession session = httpRequest.getSession(false);
            if (session != null) {
                SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY");
                session.invalidate();
                session = httpRequest.getSession(true);
                if (savedRequest != null) {
                    session.setAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY", savedRequest);
                }
            }
            
            // redirect
            String relayState = request.getParameter("RelayState");
            if (relayState != null && !relayState.isEmpty()) {
                response.sendRedirect(relayState);
            } else {
                SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
                String savedUrl = "";
                if (savedRequest != null) {
                    savedUrl = savedRequest.getRedirectUrl();
                } else {
                    savedUrl = request.getContextPath();
                }
                response.sendRedirect(savedUrl);
            }
        } catch (IOException | RuntimeException ex) {
            LogUtil.error(getClass().getName(), ex, "Error in JSON Web Token login");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
            String url = request.getContextPath() + "/web/login?login_error=1";
            response.sendRedirect(url);
        }
    }
}
