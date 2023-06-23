package com.qualys.plugins.containerSecurity;

import java.io.IOException;
import java.io.Serializable;

import com.qualys.plugins.containerSecurity.util.ContainerdClientHelper;
import com.qualys.plugins.containerSecurity.util.DockerClientHelper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class ImageShaExtractSlaveCallable extends MasterToSlaveCallable<String, IOException> implements Serializable {
    private static final long serialVersionUID = -4143159957567745621L;
    private String image;
    private String dockerUrl;
    private String dockerCert;
    private TaskListener listener;
    private String crictlBinaryPath;

    public ImageShaExtractSlaveCallable(String image, String dockerUrl, String dockerCert, String crictlBinaryPath, TaskListener listener) {
        this.image = image;
        this.dockerUrl = dockerUrl;
        this.dockerCert = dockerCert;
        this.crictlBinaryPath = crictlBinaryPath;
        this.listener = listener;
    }

    public String call() throws IOException {
        try {
            if (dockerUrl.contains("containerd")) {
                ContainerdClientHelper helper = new ContainerdClientHelper(listener.getLogger(), this.crictlBinaryPath);
                return helper.fetchImageSha(image);
            } else {
                DockerClientHelper helper = new DockerClientHelper(listener.getLogger(), dockerUrl, dockerCert);
                return helper.fetchImageSha(image, dockerCert);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}