![image](https://user-images.githubusercontent.com/16657045/229288097-9ff8cda0-5159-4817-ab7f-371934cff65a.png)

# ReconAIzer

ReconAIzer is a powerful Jython extension for Burp Suite that leverages OpenAI to help bug bounty hunters optimize their recon process. This extension automates various tasks, making it easier and faster for security researchers to identify and exploit vulnerabilities.

Once installed, ReconAIzer add a contextual menu and a dedicated tab to see the results:

![image](https://user-images.githubusercontent.com/16657045/229282506-ea5bc46b-b4d9-4f1b-9ec1-5dcd987de0bc.png)

## Prerequisites

-   Burp Suite
-   Jython Standalone Jar

## Installation

Follow these steps to install the ReconAIzer extension on Burp Suite:

### Step 1: Download Jython

1.  Download the latest Jython Standalone Jar from the official website: [https://www.jython.org/download](https://www.jython.org/download)
2.  Save the Jython Standalone Jar file in a convenient location on your computer.

### Step 2: Configure Jython in Burp Suite

1.  Open Burp Suite.
2.  Go to the "Extensions" tab.
3.  Click on the "Extensions settings" sub-tab.
4.  Under "Python Environment," click on the "Select file..." button next to "Location of the Jython standalone JAR file."
5.  Browse to the location where you saved the Jython Standalone Jar file in Step 1 and select it.
6.  Wait for the "Python Environment" status to change to "Jython (version x.x.x) successfully loaded," where x.x.x represents the Jython version.

### Step 3: Download and Install ReconAIzer

1.  Download the [latest release of ReconAIzer](https://github.com/hisxo/ReconAIzer/releases)
2.  Open the file and go on line 103 to replace _"[YOUR OPENAI API KEY]"_ with your OpenAI API key

_Note: Your OpenAI API key can be found here: [https://platform.openai.com/account/api-keys](https://platform.openai.com/account/api-keys)._

### Step 4: Download and Install ReconAIzer

1.  Open Burp Suite
2.  Go back to the "Extensions" tab in Burp Suite.
3.  Click the "Add" button.
4.  In the "Add extension" dialog, select "Python" as the "Extension type."
5.  Click on the "Select file..." button next to "Extension file" and browse to the location where you saved the `ReconAIzer.py` file in Step 3.1. Select the file and click "Open."
6.  Make sure the "Load" checkbox is selected and click the "Next" button.
7.  Wait for the extension to be loaded. You should see a message in the "Output" section stating that the ReconAIzer extension has been successfully loaded.

Congratulations! You have successfully installed the ReconAIzer extension in Burp Suite. You can now start using it to enhance your bug bounty hunting experience.

**Note: Feel free to suggest prompts improvements or anything you would like to see on ReconAIzer!**

Happy bug hunting!

![image](https://user-images.githubusercontent.com/16657045/229282837-da0c0314-0882-4ef2-9203-018682330f76.png)
