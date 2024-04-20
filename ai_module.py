from openai import OpenAI
from sql_module import read_table_by_key
import os
import json

def set_api_key():
	if os.path.exists("./API_KEY"):
		f = open("API_KEY")
		os.environ["OPENAI_API_KEY"] = f.read()
		f.close()
	else:
		os.environ["OPENAI_API_KEY"] = input("Enter your OpenAI API key: \n")
		print("Would you like to save your API key to a local file? This will remove the need to enter the key every time.(y/n)\n")
		choice = input()
		if choice == "y":
			f = open("API_KEY", "w")
			f.write(os.environ["OPENAI_API_KEY"])
			f.close()
		else:
			pass	

def check_if_apikey_is_set():
	key = os.environ.get("OPENAI_API_KEY")
	if key == None:
		set_api_key()
	else:
		return

# https://platform.openai.com/docs/guides/text-generation
# this returns in the format of vendor, username, password
def get_parameters(req):
	check_if_apikey_is_set()
	client = OpenAI()
	response = client.chat.completions.create(
	model="gpt-3.5-turbo",
	messages=[
		{"role": "system", "content": "You are a helpful assistant used to gather data from an HTTP response"},
		{"role": "user", "content": f"This is a response from a webpage I am trying to log in to: {req}"},
		{"role": "user", "content": f"Respond in this format: VENDOR=[vendor],USERNAME=[username_paramter],PASSWORD=[password_parameter]"},
		{"role": "user", "content": "Who is the vendor of this webpage? (Examples: Hewlett-Packard, Dell, etc.) What are the post parameters required to respond to this request in order to login?"}
	]
	)
	#print(response.choices[0].message.content)
	result = parse_ai_output(response.choices[0].message.content)
	#print(result)
	return result

#function to parse the AI Output. It needs error handling incase the AI freaks out
def parse_ai_output(resp):
	parsed_output = []
	r = resp.split(",")
	for i in r:
		param = i.split("=")[1]
		parsed_output.append(param)
	return parsed_output

#function to generate report based off of data in vulns table
def generate_report(data, data2):
	check_if_apikey_is_set()
	client = OpenAI()
	response = client.chat.completions.create(
	model="gpt-4-turbo",
	messages=[
		{"role": "system", "content": "You are an assistant used to generate reports detailing the findings from Vulnerability Scans."},
		{"role": "user", "content": f"This is a table which contains the found vulnerabilities from the test: {data}"},
		{"role": "user", "content": f"You can also use the table containing enumeration data from the test, if you wish: {data2}"},
		{"role": "user", "content": "Create a report using the given data. Detail the hostname, what the vulnerability is, \
		how severe it is, and how it can be fixed. Include a small disclaimer at the bottom mentioning how this report was AI-generated"}
	]
	)
	# print(response.choices[0].message.content)
	return response.choices[0].message.content


def cve_lookup(service_version):
	check_if_apikey_is_set()
	client = OpenAI()
	response = client.chat.completions.create(
	model="gpt-4-turbo",
	messages=[
		{"role": "system", "content": "You are an assistant used to find the CVE ID associated with vulnerabilities in software. You take in software and their version, and return relevant CVEs"},
		{"role": "user", "content": f"Return ONLY the CVE ID. Return multiple if there are multiple. Return all that you find. If no CVE ID exists, simply return the string 'None Found'"},
		{"role": "user", "content": f"Here is the software version: {service_version}"}
	]
	)
	# print(response.choices[0].message.content)
	print(response.choices[0].message.content)



#https://platform.openai.com/docs/assistants/overview?context=with-streaming
### THE BELOW FUNCTION IS EXPERIMENTAL AND UNFINISHED!
def cve_lookup_experimental():

	check_if_apikey_is_set()

	client = OpenAI()

	assistant = client.beta.assistants.create(
  	name="CVE-Lookup",
  	instructions="You take in the name and version of a service, and reference the CVE DB files I've given you, to find valid CVEs. Provide links for more information if available",
  	tools=[{"type": "file_search"}],
  	model="gpt-4-turbo-2024-04-09",
	)

	vector_id = store_cve_db(client)

	assistant = client.beta.assistants.update(
  	assistant_id=assistant.id,
  	tool_resources={"file_search": {"vector_store_ids": [vector_id]}},
	)

		# Upload the user provided file to OpenAI
	message_file = client.files.create(
	file=open("./nvdcve-1.1-recent.json", "rb"), purpose="assistants"
	)
	
	# Create a thread and attach the file to the message
	thread = client.beta.threads.create(
	messages=[
		{
		"role": "user",
		"content": "Windows 11",
		# Attach the new file to the message.
		"attachments": [
			{ "file_id": message_file.id, "tools": [{"type": "file_search"}] }
		],
		}
	]
	)

	
	
	# The thread now has a vector store with that file in its tool resources.
	print(thread.tool_resources.file_search)

	run = client.beta.threads.runs.create_and_poll(
    thread_id=thread.id, assistant_id=assistant.id
	)	

	messages = list(client.beta.threads.messages.list(thread_id=thread.id, run_id=run.id))

	message_content = messages[0].content[0].text
	annotations = message_content.annotations
	citations = []
	for index, annotation in enumerate(annotations):
		message_content.value = message_content.value.replace(annotation.text, f"[{index}]")
		if file_citation := getattr(annotation, "file_citation", None):
			cited_file = client.files.retrieve(file_citation.file_id)
			citations.append(f"[{index}] {cited_file.filename}")

	print(message_content.value)
	print("\n".join(citations))
	

#https://nvd.nist.gov/vuln/data-feeds
def store_cve_db(client):
		# Create a vector store caled "Financial Statements"
	vector_store = client.beta.vector_stores.create(name="Financial Statements")
	
	# Ready the files for upload to OpenAI 
	file_paths = ["./nvdcve-1.1-recent.json"]
	file_streams = [open(path, "rb") for path in file_paths]
	
	# Use the upload and poll SDK helper to upload the files, add them to the vector store,
	# and poll the status of the file batch for completion.
	file_batch = client.beta.vector_stores.file_batches.upload_and_poll(
	vector_store_id=vector_store.id, files=file_streams
	)
	
	# You can print the status and the file counts of the batch to see the result of this operation. 
	print(file_batch.status)
	print(file_batch.file_counts)
	return vector_store.id


# BELOW IS TEST FUNCTIONS - REMOVE LATER
# data = read_table_by_key("vulns","host","192.168.56.110")
# generate_report(data)
#cve_lookup_experimental()
