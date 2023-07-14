package com.qualys.plugins.containerSecurity.util;

import hudson.AbortException;
import qshaded.com.google.gson.JsonArray;
import qshaded.com.google.gson.JsonElement;
import qshaded.com.google.gson.JsonObject;
import qshaded.com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.logging.Logger;

public class ContainerdClientHelper {
    private final static Logger logger = Logger.getLogger(Helper.class.getName());
    private final String exportPathCmd = "export PATH=$PATH:";

    private final String crictlVersionCmd = "crictl version";
    private final String listContainersCmd = "crictl ps --output json";
    private final String inspectContainerCmd = "crictl inspect ";
    private final String inspectImageCmd = "crictl inspecti ";
    private final String tagImageCmd = "nerdctl -n k8s.io tag ";
    private PrintStream buildLogger;
    private String crictlBinaryPath;


    public ContainerdClientHelper() {
    }

    public ContainerdClientHelper(PrintStream buildLogger, String crictlBinaryPath) {
        this.buildLogger = buildLogger;
        this.crictlBinaryPath = crictlBinaryPath;
    }

    public boolean isCICDSensorUp() throws Exception {
        this.validateCrictlBinaryPath();
        JsonArray containerArray = getListOfContainers();
        for (JsonElement container : containerArray) {
            JsonObject containerObj = container.getAsJsonObject();
            if (containerObj.has("metadata") && containerObj.get("metadata").getAsJsonObject().get("name").getAsString().toLowerCase().equals("qualys-container-sensor")) {
                if (containerObj.has("state") && containerObj.get("state").getAsString().equals("CONTAINER_RUNNING")) {
                    return checkForCICDMode(buildLogger, containerObj.get("id").getAsString());
                } else {
                    buildLogger.println("Qualys CS sensor container is not runnning. Sensor won't be able to scan the image. Please check the sensor container.");
                    throw new AbortException(
                            "Qualys CS sensor container is not runnning. Sensor won't be able to scan the image. Please check the sensor container.");
                }
            }
        }
        buildLogger.println("Qualys CS sensor is not available on the host. Sensor won't be able to scan the image. Please check the sensor container.");
        throw new AbortException(
                "Qualys CS sensor is not available on the host. Sensor won't be able to scan the image. Please check the sensor container.");
    }

    private JsonArray getListOfContainers() {
        String command = exportPathCmd + this.crictlBinaryPath + ";" + listContainersCmd;
        JsonObject containers = null;
        JsonArray containersArray = null;
        String containersInfo = this.executeCommand(command);
        try {
            if (containersInfo.startsWith("{") && containersInfo.contains("containers")) {
                containers = JsonParser.parseString(containersInfo).getAsJsonObject();
                containersArray = JsonParser.parseString(containers.get("containers").toString()).getAsJsonArray();
            } else {
                buildLogger.println("Failed to get containers list .Please check if crictl binary is added to the path.");
                throw new AbortException(
                        "Failed to get containers list .Please check if crictl binary is added to the path.");
            }
            return containersArray;
        } catch (IOException e) {
            buildLogger.println("Failed to parse the " + command + " output " +"Failed to get containers list .Please check if crictl binary is added to the path.");
        }
        return null;
    }

    private boolean checkForCICDMode(PrintStream buildLogger, String containerID) throws IOException {
        String command = exportPathCmd + this.crictlBinaryPath + ";" + inspectContainerCmd + containerID;
        String sensorInfo = this.executeCommand(command);
        try {
            JsonObject sensorInfoJson = JsonParser.parseString(sensorInfo).getAsJsonObject();
            //buildLogger.println("arg is " + sensorInfoJson.get("info").getAsJsonObject().get("config").getAsJsonObject().get("args").isJsonArray());
            JsonArray  sensorArguments=sensorInfoJson.get("info").getAsJsonObject().get("config").getAsJsonObject().get("args").getAsJsonArray();
                    for (JsonElement arg:sensorArguments)
                    {
                        if(arg.getAsString().equals("--cicd-deployed-sensor")||arg.getAsString().equals("-c"))
                            return true;
                    }
        } catch (Exception e) {
            String errorMsg = "Failed to check if the sensor is running in CICD mode ; Reason : " + e.getMessage();
            logger.info(errorMsg);
            throw new AbortException(errorMsg);
        }
        return false;
    }

    public String fetchImageSha(String image) throws AbortException {
        String command = exportPathCmd + this.crictlBinaryPath + ";" + inspectImageCmd + image;
        String imagesha = "";
        String imageShaOutput = this.executeCommand(command);
        try {
            if (!imageShaOutput.isEmpty() && imageShaOutput.contains("status")) {
                JsonObject imageInfo = JsonParser.parseString(imageShaOutput).getAsJsonObject();
                imagesha = imageInfo.get("status").getAsJsonObject().get("id").getAsString();
                String[] imageIds = imagesha.split(":");
                imagesha = imageIds[1];
            } else {
                buildLogger.println("Failed to extract image sha associated with " + image);
                throw new AbortException("Failed to extract image sha associated with " + image);
            }
        } catch (Exception e) {
            String errorMsg = "Failed to extract image sha associated with " + image + " ; Reason : " + e.getMessage();
            logger.info(errorMsg);
            throw new AbortException(errorMsg);
        }
        return imagesha;
    }

    public boolean tagImage(String imageIdOrName, String imageSha) throws AbortException, IOException {

        String command = exportPathCmd + this.crictlBinaryPath + "/bin;" + tagImageCmd + imageIdOrName + " qualys_scan_target:" + imageSha;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("bash", "-c", command);
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            String jsonString = "";
            while ((line = reader.readLine()) != null) {
                jsonString = jsonString + line;
            }
            if(jsonString.trim().equals("qualys_scan_target:"+imageSha))
                buildLogger.println("image tagged "+ imageIdOrName+" successfully " );
            else
                throw new AbortException("Failed to tag the image " + jsonString);
        } catch (Exception e) {
            for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
            buildLogger.println("Failed to tag the image " + imageIdOrName
                    + " with qualys_scan_target.. Reason : " + e.getMessage());
            throw new AbortException("Failed to tag the image " + imageIdOrName + " with qualys_scan_target.. Reason : "
                    + e.getMessage());
        }
        return true;

    }

    public void validateCrictlBinaryPath() throws AbortException, IOException {
        String command = exportPathCmd + this.crictlBinaryPath + ";" + crictlVersionCmd;
        String versionInfo = this.executeCommand(command);
        if (!versionInfo.toLowerCase().contains("version"))
            throw new AbortException("Crictl Binary path is not set properly.");
    }

    private String executeCommand(String command) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("bash", "-c", command);
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            String commandOutput = "";
            while ((line = reader.readLine()) != null) {
                commandOutput = commandOutput + line;
            }
            process.destroy();
            return commandOutput;
        } catch (IOException e) {
            throw new RuntimeException("Failed to execute command " + command
                    + e.getMessage());
        }
    }
}
