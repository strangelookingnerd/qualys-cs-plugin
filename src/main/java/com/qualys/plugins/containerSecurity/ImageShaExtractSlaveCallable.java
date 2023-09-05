package com.qualys.plugins.containerSecurity;

import com.qualys.plugins.containerSecurity.util.ContainerdNerdctlClientHelper;
import com.qualys.plugins.containerSecurity.util.Helper;
import java.io.IOException;
import java.io.Serializable;

import com.qualys.plugins.containerSecurity.util.DockerClientHelper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class ImageShaExtractSlaveCallable extends MasterToSlaveCallable<String, IOException> implements Serializable {
    private static final long serialVersionUID = -4143159957567745621L;
    private String image;
    private String dockerUrl;
    private String dockerCert;
    private TaskListener listener;

    public ImageShaExtractSlaveCallable(String image, String dockerUrl, String dockerCert, TaskListener listener) {
        this.image = image;
        this.dockerUrl = dockerUrl;
        this.dockerCert = dockerCert;
        this.listener = listener;
    }

    public String call() throws IOException {
        if (Helper.isRuntimeDocker(this.dockerUrl)) {
            DockerClientHelper helper = new DockerClientHelper(listener.getLogger(), dockerUrl, dockerCert);
            return helper.fetchImageSha(image, dockerCert);
        } else {
            ContainerdNerdctlClientHelper helper = new ContainerdNerdctlClientHelper(listener.getLogger(), dockerUrl);
            return helper.fetchImageSha(image);
        }
    }
}