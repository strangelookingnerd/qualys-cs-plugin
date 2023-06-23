package com.qualys.plugins.containerSecurity;

import java.io.IOException;
import java.io.Serializable;

import com.qualys.plugins.containerSecurity.util.ContainerdClientHelper;
import com.qualys.plugins.containerSecurity.util.DockerClientHelper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class CheckSensorSlaveCallable extends MasterToSlaveCallable<Boolean, IOException> implements Serializable {

    private static final long serialVersionUID = 1L;
    private String dockerUrl;
    private String dockerCert;
    private TaskListener listener;
    private String crictlBinaryPath;

    public CheckSensorSlaveCallable(String dockerUrl, String dockerCert, String crictlBinaryPath, TaskListener listener) {

        this.dockerUrl = dockerUrl;
        this.dockerCert = dockerCert;
        this.crictlBinaryPath = crictlBinaryPath;
        this.listener = listener;
    }

    public Boolean call() throws IOException {
        try {
            if (dockerUrl.contains("containerd")) {
                ContainerdClientHelper helper = new ContainerdClientHelper(listener.getLogger(), this.crictlBinaryPath);
                return helper.isCICDSensorUp();
            } else {
                DockerClientHelper helper = new DockerClientHelper(listener.getLogger(), dockerUrl, dockerCert);
                return helper.isCICDSensorUp();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


