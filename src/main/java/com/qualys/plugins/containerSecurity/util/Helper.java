package com.qualys.plugins.containerSecurity.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Collections;


import org.apache.commons.lang.StringUtils;

public class Helper{
   
	private static final long serialVersionUID = 1L;
	public static final String GET_IMAGE_LIST_API_PATH_FORMAT = "/csapi/v1.2/images?pageNumber=0&pageSize=10&sort=created";
    public static final String GET_SCAN_RESULT_API_PATH_FORMAT = "/csapi/v1.2/images/%s"; 
    public static final String CVE_REGEX = "CVE-\\d{4}-\\d{4,7}";
    
    public static final String IMAGE_ID_REGEX = "^([A-Fa-f0-9]{12}|[A-Fa-f0-9]{64})$";
    public static final String IMAGE_NAME_REGEX = "^(?:(?=[^:\\/]{4,253})(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*(?::[0-9]{1,5})?/)?((?![:\\/._-])(?:[a-z0-9._-]*)(?<![:\\/._-])(?:/(?![._-])[a-z0-9._-]+(?<![._-]))*)(?::(?![.-])[a-zA-Z0-9_.-]{1,128})?$";
	public static final String IMAGE_ENV_VAR = "\\$\\{(.*?)}";

	public static boolean isRuntimeDocker(String url){
		return url.startsWith("unix://") || url.startsWith("tcp://");
	}
    
    public static boolean isValidCVEList(String cveList) {
    	if(cveList != null && !StringUtils.isBlank(cveList)) {
    		List<String> cves = Arrays.asList(cveList.split(","));
    		Pattern patt = Pattern.compile(CVE_REGEX);
    		for(String el: cves) {
                Matcher matcher = patt.matcher(el);
                if (!(matcher.matches())) {
                    return false;
                }
    		}
    	}
    	return true;
    }
    public static void createNewFile(String rootDir, String filename, String content, PrintStream buildLogger) {
  	  	   	
    	 File f = new File(rootDir + File.separator + filename + ".json");
	    if(!f.getParentFile().exists()){
	        if (f.getParentFile().mkdirs()) { 
	        	System.out.println("Directory is created"); 
	        } 
	        else {  
	            System.out.println("Directory cannot be created"); 
	        } 
	    }

	    if(!f.exists()){
	        try {
	            if (!f.createNewFile()) {
	            	 buildLogger.println("File already exists or failed creating file " + filename);
	            }
	        } catch (Exception e) {
	            e.printStackTrace();
	            buildLogger.println("Failed creating file " + filename + ", reason =" + e.getMessage());
	        }
	    }
	    try {
	        File dir = new File(f.getParentFile(), f.getName());
	        Writer w = new OutputStreamWriter(new FileOutputStream(dir), "UTF-8");
	        PrintWriter writer = new PrintWriter(w);
	        writer.print(content);
	        writer.close();
	    } catch (FileNotFoundException e) {
	    	e.printStackTrace();
	    	buildLogger.println("Failed writing to file " + filename + ", reason =" + e.getMessage());
	    } catch (IOException e) {
	    	e.printStackTrace();
	    	buildLogger.println("Failed writing to file " + filename + ", reason =" + e.getMessage());
		}
    }
    
    public static void createZip(String zipFile, String srcDir, PrintStream buildLogger) {
    	       
    	FileOutputStream fos = null;
    	ZipOutputStream zos = null;
    	FileInputStream fis = null;
        try {
             
            // create byte buffer
            byte[] buffer = new byte[1024];
            fos = new FileOutputStream(zipFile);
 
            zos = new ZipOutputStream(fos);
 
            File dir = new File(srcDir);
 
            //Get only .txt files
            File[] files = dir.listFiles(new FilenameFilter() { 
                public boolean accept(File dir, String filename)
                	{ return filename.endsWith(".json"); }
            	} );
            
            if (files == null) {
            	return;
            }
            for (int i = 0; i < files.length; i++) {
            		System.out.println("Adding file: " + files[i].getName());
            		
            		fis = new FileInputStream(files[i]);
            		
            		zos.putNextEntry(new ZipEntry(files[i].getName()));
            		int length;
            		while ((length = fis.read(buffer)) > 0) {
            			zos.write(buffer, 0, length);
            		}
            		zos.closeEntry();
            		
            		fis.close();
            		//delete file
            		if(! files[i].getName().equals("qualys_images_summary.json")) {            			
            			if (files[i].delete()) {
            				System.out.println(files[i].getName() + " file moved to zip and deleted.");
            			}
            		}
            }
            zos.close();
        }
        catch (IOException ioe) {
        	buildLogger.println("Error creating zip file" + ioe);
        }finally {
        	if (zos != null) {
        		try {
					zos.close();
				} catch (IOException e) {
					buildLogger.println("Error creating zip file" + e);
				}
        	}
        	if (fis != null) {
        		try {
					fis.close();
				} catch (IOException e) {
					buildLogger.println("Error creating zip file" + e);
				}
        	}
        }
    }
}
