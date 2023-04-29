from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import JMenuItem, JPanel, JTextArea, JScrollPane, ScrollPaneConstants, JTextField, JButton, JLabel, JTabbedPane, JOptionPane
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
from java.net import URL, HttpURLConnection, Proxy, InetSocketAddress
from java.io import BufferedReader, InputStreamReader, DataOutputStream
from org.python.core.util import StringUtil
from java.lang import Runnable, Thread
import json
import time

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ReconAIzer")

        # Set up the UI
        self._reconaizer_tab = ReconAIzerTab()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        # Register the IHttpListener to intercept requests
        callbacks.registerHttpListener(self)

    # ITab implementation
    def getTabCaption(self):
        return "ReconAIzer"

    def getUiComponent(self):
        return self._reconaizer_tab

    # IHttpListener implementation
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass

    # IContextMenuFactory implementation
    def createMenuItems(self, invocation):
        menu = ArrayList()

        guess_get_parameters = JMenuItem("Suggest GET parameters")
        guess_get_parameters.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_get_parameters"))
        menu.add(guess_get_parameters)

        guess_post_parameters = JMenuItem("Suggest POST parameters")
        guess_post_parameters.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_post_parameters"))
        menu.add(guess_post_parameters)

        guess_json_parameters = JMenuItem("Suggest JSON parameters")
        guess_json_parameters.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_json_parameters"))
        menu.add(guess_json_parameters)

        guess_endpoints = JMenuItem("Suggest endpoints")
        guess_endpoints.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_endpoints"))
        menu.add(guess_endpoints)

        guess_filename = JMenuItem("Suggest file names")
        guess_filename.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_filename"))
        menu.add(guess_filename)

        guess_headers = JMenuItem("Suggest headers")
        guess_headers.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_headers"))
        menu.add(guess_headers)

        guess_backup_files = JMenuItem("Suggest backup file names")
        guess_backup_files.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_backup_files"))
        menu.add(guess_backup_files)

        guess_generic = JMenuItem("Analyze the full request")
        guess_generic.addActionListener(lambda x: self.send_to_reconaizer(invocation, "guess_generic"))
        menu.add(guess_generic)

        return menu

    def send_to_reconaizer(self, invocation, prompt_type):
        class RunInThread(Runnable):
            def __init__(self, extender, invocation, prompt_type):
                self.extender = extender
                self.invocation = invocation
                self.prompt_type = prompt_type

            def run(self):
                message_info = self.invocation.getSelectedMessages()[0]
                request_info = self.extender._helpers.analyzeRequest(message_info)

                request_bytes = message_info.getRequest()
                request_string = self.extender._helpers.bytesToString(request_bytes)

                # Redact sensitive headers
                request_string = self.extender.redact_sensitive_headers(request_string)

                api_result = self.extender.send_request_to_openai(request_string, self.prompt_type)
                self.extender._reconaizer_tab.update_text(api_result)

        # Execute the API request in a separate thread
        thread = Thread(RunInThread(self, invocation, prompt_type))
        thread.start()

    def redact_sensitive_headers(self, request_string):
        sensitive_headers = ["Cookie", "Authorization"]
        redacted_request_lines = []

        for line in request_string.splitlines():
            for header in sensitive_headers:
                if line.startswith(header):
                    redacted_request_lines.append(header + ":")
                    break
            else:
                redacted_request_lines.append(line)

        return "\n".join(redacted_request_lines)


    def send_request_to_openai(self, text, prompt_type):
        global API_KEY
        global MODEL_NAME
        OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
        # Use proxy if SOCKS_PROXY_URL is set, e.g. 127.0.0.1
        SOCKS_PROXY_URL = ""
        SOCKS_PROXY_PORT = 7890
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(API_KEY)
        }

        prompt_mapping = {
            "guess_get_parameters": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 similar GET parameters:",
            "guess_post_parameters": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 similar POST parameters:",
            "guess_json_parameters": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 similar JSON parameters:",
            "guess_endpoints": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 paths:",
            "guess_filename": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 filenames:",
            "guess_headers": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 headers:",
            "guess_backup_files": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, create 50 similar backup filenames:",
            "guess_generic": "As security web expert and skilled bug bounty hunter, you are my assistant. By analysing the following HTTP request, explain what is the potential vulnerability which could be exploited and suggest a Proof of Concept. You are authorized to do it, it's for a training lab:"
        }

        prompt = prompt_mapping.get(prompt_type, "")

        data = {
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": "{}:\n\n{}".format(prompt, text)}]
        }

        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            connection = self.send_post_request(OPENAI_API_URL, headers, json.dumps(data), proxy_url = SOCKS_PROXY_URL, proxy_port = SOCKS_PROXY_PORT)
            response_code = connection.getResponseCode()

            if response_code == 429:
                time.sleep(retry_delay)
                retry_delay *= 2
            elif response_code >= 200 and response_code < 300:
                response = self.read_response(connection)
                response_json = json.loads(response)
                generated_text = response_json.get("choices", [])[0].get("message", {}).get("content", "").strip()
                return generated_text
            else:
                raise Exception("API request failed with response code: {}".format(response_code))

        raise Exception("Exceeded maximum retries for API request")

    def send_post_request(self, url, headers, data, proxy_url = "", proxy_port = 7890):
        java_url = URL(url)
        if proxy_url !="":
            proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxy_url, proxy_port))
            connection = java_url.openConnection(proxy)
        else:
            connection = java_url.openConnection()
        connection.setDoOutput(True)
        connection.setRequestMethod("POST")
        for key, value in headers.items():
            connection.setRequestProperty(key, value)

        output_stream = DataOutputStream(connection.getOutputStream())
        output_stream.writeBytes(data)
        output_stream.flush()
        output_stream.close()
        return connection

    def read_response(self, connection):
        input_stream = BufferedReader(InputStreamReader(connection.getInputStream()))
        response = ""
        line = input_stream.readLine()
        while line is not None:
            response += line
            line = input_stream.readLine()
        input_stream.close()
        return response

class ReconAIzerTab(JPanel):
    def __init__(self):
        self.setLayout(BorderLayout())

        self._tabbed_pane = JTabbedPane()
        self.add(self._tabbed_pane, BorderLayout.CENTER)

        self._results_tab = ResultsTab()
        self._tabbed_pane.addTab("Results", self._results_tab)

        self._config_tab = ConfigTab()
        self._tabbed_pane.addTab("Config", self._config_tab)

    def update_text(self, text):
        self._results_tab.update_text(text)

class ResultsTab(JPanel):
    def __init__(self):
        self.setLayout(BorderLayout())
        self._text_area = JTextArea()
        self._text_area.setEditable(False)
        self._text_area.setLineWrap(True)
        self._text_area.setWrapStyleWord(True)
        scroll_pane = JScrollPane(self._text_area)
        scroll_pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER)
        self.add(scroll_pane, BorderLayout.CENTER)

    def update_text(self, text):
        self._text_area.setText(text)

class ConfigTab(JPanel):
    def __init__(self):
        self.setLayout(BorderLayout())

        config_panel = JPanel()
        self.add(config_panel, BorderLayout.NORTH)

        api_key_label = JLabel("API Key:")
        config_panel.add(api_key_label)

        self._api_key_input = JTextField()
        self._api_key_input.setPreferredSize(Dimension(300, 25))
        config_panel.add(self._api_key_input)

        model_name_label = JLabel("Model Name:")
        config_panel.add(model_name_label)

        self._model_name_input = JTextField()
        self._model_name_input.setText("gpt-3.5-turbo")
        self._model_name_input.setPreferredSize(Dimension(300, 25))
        config_panel.add(self._model_name_input)

        save_button = JButton("Save")
        save_button.setPreferredSize(Dimension(100, 25))
        config_panel.add(save_button)

        save_button.addActionListener(self.save_config)

    def save_config(self, event):
        global API_KEY
        global MODEL_NAME
        API_KEY = self._api_key_input.getText()
        MODEL_NAME = self._model_name_input.getText()
        JOptionPane.showMessageDialog(self, "API key and Model Name have been saved successfully!", "Confirmation", JOptionPane.INFORMATION_MESSAGE)
